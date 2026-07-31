#!/usr/bin/env python3
"""Validate and finalize a paired clean-source T3-1 live reproduction."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
from typing import Any


EXPECTED_COMMIT = "26cbc33a418a292e3b3949be69155898d751bd6e"
TRACE_PATTERN = re.compile(
    r"factor\[(\d+)\] actual_total\[(\d+)\] actual_ul\[(\d+)\] "
    r"actual_dl\[(\d+)\] reported_total\[(\d+)\] reported_ul\[(\d+)\] "
    r"reported_dl\[(\d+)\]"
)


class PairError(Exception):
    pass


def run(*arguments: str) -> str:
    completed = subprocess.run(arguments, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise PairError(f"{' '.join(arguments)}: {completed.stderr.strip()}")
    return completed.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_checksums(directory: Path) -> int:
    checksum_file = directory / "SHA256SUMS"
    if not checksum_file.is_file():
        raise PairError(f"missing {checksum_file}")
    count = 0
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split(None, 1)
        path = directory / relative.strip()
        if not path.is_file() or sha256(path) != expected:
            raise PairError(f"checksum mismatch: {path}")
        count += 1
    return count


def tshark_rows(path: Path, display_filter: str, fields: tuple[str, ...]) -> list[list[str]]:
    arguments = [
        "tshark",
        "-r",
        str(path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=a",
    ]
    for field in fields:
        arguments.extend(("-e", field))
    rows: list[list[str]] = []
    for line in run(*arguments).splitlines():
        values = line.split("\t")
        values.extend("" for _ in range(len(fields) - len(values)))
        rows.append(values)
    return rows


def pfcp_usage(directory: Path) -> list[tuple[int, int, int]]:
    rows = tshark_rows(
        directory / "pfcp.pcap",
        "pfcp.volume_measurement.tovol",
        (
            "pfcp.volume_measurement.tovol",
            "pfcp.volume_measurement.ulvol",
            "pfcp.volume_measurement.dlvol",
        ),
    )
    values = [(int(total), int(uplink), int(downlink)) for total, uplink, downlink in rows]
    if not values or any(total != uplink + downlink for total, uplink, downlink in values):
        raise PairError(f"invalid PFCP usage tuples in {directory}")
    return values


def gy_usage(directory: Path) -> list[tuple[int, int, int]]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1 "
        "&& diameter.CC-Request-Type == 2",
        (
            "diameter.CC-Input-Octets",
            "diameter.CC-Output-Octets",
        ),
    )
    values = []
    for input_octets, output_octets in rows:
        uplink = int(input_octets or "0")
        downlink = int(output_octets or "0")
        values.append((uplink + downlink, uplink, downlink))
    if not values:
        raise PairError(f"no Gy CCR-U usage in {directory}")
    return values


def accepted_pfcp_responses(directory: Path) -> int:
    rows = tshark_rows(
        directory / "pfcp.pcap",
        "pfcp.msg_type == 57",
        ("pfcp.cause",),
    )
    return sum(1 for row in rows if row[0] == "1")


def accepted_cca_updates(directory: Path) -> int:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 0 "
        "&& diameter.CC-Request-Type == 2",
        ("diameter.Result-Code",),
    )
    return sum(1 for row in rows if "2001" in row[0].split(","))


def trace_usage(directory: Path) -> tuple[list[tuple[int, int, int]], list[tuple[int, int, int]]]:
    text = (directory / "inflation_trace.txt").read_text(encoding="utf-8")
    matches = [tuple(int(value) for value in match.groups()) for match in TRACE_PATTERN.finditer(text)]
    if not matches:
        raise PairError("attack inflation trace is empty")
    factors = {row[0] for row in matches}
    if factors != {5}:
        raise PairError(f"unexpected mutation factors: {sorted(factors)}")
    actual = [(row[1], row[2], row[3]) for row in matches]
    reported = [(row[4], row[5], row[6]) for row in matches]
    if any(
        reported_tuple != tuple(value * 5 for value in actual_tuple)
        for actual_tuple, reported_tuple in zip(actual, reported)
    ):
        raise PairError("producer trace does not satisfy exact x5 mutation")
    return actual, reported


def charge(directory: Path) -> dict[str, int]:
    data = json.loads((directory / "ocs_balance_summary.json").read_text(encoding="utf-8"))
    before = data["before_cents"]
    after = data["after_cents"]
    charged = data["charged_cents"]
    if before - after != charged:
        raise PairError(f"OCS arithmetic mismatch in {directory}")
    return {"before_cents": before, "after_cents": after, "charged_cents": charged}


def environment(directory: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (directory / "environment.txt").read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        values[key] = value
    return values


def preflight(directory: Path, expected_mode: str) -> dict[str, Any]:
    data = json.loads((directory / "preflight.json").read_text(encoding="utf-8"))
    if data.get("mode", "attack") != expected_mode:
        raise PairError(f"{directory}: unexpected preflight mode")
    failed = [item["check"] for item in data["checks"] if not item["passed"]]
    if failed:
        raise PairError(f"{directory}: failed preflight checks: {failed}")
    return data


def packet_count(path: Path) -> int:
    output = run("capinfos", "-Tm", "-c", str(path))
    rows = list(csv.reader(io.StringIO(output)))
    if len(rows) != 2:
        raise PairError(f"cannot parse capinfos output for {path}")
    return int(rows[1][1])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    attack = args.attack.resolve()
    baseline = args.baseline.resolve()
    output = args.output.resolve()

    attack_checksum_count = verify_checksums(attack)
    baseline_checksum_count = verify_checksums(baseline)
    attack_environment = environment(attack)
    baseline_environment = environment(baseline)
    preflight(attack, "attack")
    preflight(baseline, "baseline")

    for values in (attack_environment, baseline_environment):
        if values.get("open5gs_commit") != EXPECTED_COMMIT:
            raise PairError("Open5GS commit mismatch")
        if values.get("kernel") != "6.17.0-40-generic":
            raise PairError("kernel mismatch")

    baseline_pfcp = pfcp_usage(baseline)
    baseline_gy = gy_usage(baseline)
    attack_pfcp = pfcp_usage(attack)
    attack_gy = gy_usage(attack)
    trace_actual, trace_reported = trace_usage(attack)
    baseline_charge = charge(baseline)
    attack_charge = charge(attack)
    baseline_packets = packet_count(baseline / "gtpu.pcap")
    attack_packets = packet_count(attack / "gtpu.pcap")

    relations = {
        "identical_gtpu_packet_count": baseline_packets == attack_packets and baseline_packets > 0,
        "baseline_pfcp_equals_gy": baseline_pfcp == baseline_gy,
        "baseline_equals_attack_actual": baseline_pfcp == trace_actual,
        "attack_trace_exact_x5": trace_reported
        == [tuple(value * 5 for value in item) for item in trace_actual],
        "attack_trace_equals_pfcp": trace_reported == attack_pfcp,
        "attack_pfcp_equals_gy": attack_pfcp == attack_gy,
        "pfcp_reports_accepted": accepted_pfcp_responses(attack) == len(attack_pfcp),
        "cca_updates_accepted": accepted_cca_updates(attack) == len(attack_gy),
        "backend_charge_increased": attack_charge["charged_cents"]
        > baseline_charge["charged_cents"],
    }
    failed_relations = [name for name, passed in relations.items() if not passed]
    if failed_relations:
        raise PairError(f"failed semantic relations: {failed_relations}")

    result = {
        "schema_version": "1.0",
        "run_id": f"paired_{baseline.name}__{attack.name}",
        "audit_id": "T3-A17",
        "legacy_threat_id": "T3-1",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "kernel": "6.17.0-40-generic",
        "open5gs_commit": EXPECTED_COMMIT,
        "mutation_factor": 5,
        "gtpu_packet_count_each": baseline_packets,
        "report_count": len(attack_pfcp),
        "baseline_pfcp_usage": baseline_pfcp,
        "attack_actual_usage": trace_actual,
        "attack_reported_usage": trace_reported,
        "baseline_usage_sum": sum(item[0] for item in baseline_pfcp),
        "attack_reported_usage_sum": sum(item[0] for item in attack_pfcp),
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents": attack_charge["charged_cents"]
        - baseline_charge["charged_cents"],
        "g1_wire_acceptance": True,
        "g2_state_effect": True,
        "g3_backend_effect": True,
        "classification": "E2E",
        "semantic_relations": relations,
        "input_checksum_counts": {
            "baseline": baseline_checksum_count,
            "attack": attack_checksum_count,
        },
        "claim_boundary": (
            "This paired live run validates three accepted CCR-U/CCA-U exchanges. "
            "It does not claim that CCR-I/T were captured in this pair."
        ),
    }

    output.mkdir(parents=True, exist_ok=False)
    result_path = output / "paired_result.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (output / "SOURCE_RUNS.txt").write_text(
        f"baseline={baseline.name}\nattack={attack.name}\n", encoding="utf-8"
    )
    (output / "PAIR_VALIDATION.md").write_text(
        "\n".join(
            (
                "# T3-1 Paired Live Validation",
                "",
                "Result: `E2E PASS`.",
                "",
                f"- Kernel: `{result['kernel']}`",
                f"- Identical GTP-U packet count: `{baseline_packets:,}` per run",
                f"- Baseline usage: `{result['baseline_usage_sum']:,}` bytes",
                f"- Attack reported usage: `{result['attack_reported_usage_sum']:,}` bytes",
                f"- Mutation: exact `×{result['mutation_factor']}` for all "
                f"`{result['report_count']}` reports",
                f"- OCS charge: `{result['baseline_charge_cents']}¢` baseline → "
                f"`{result['attack_charge_cents']}¢` attack",
                f"- Charge delta: `+{result['charge_delta_cents']}¢`",
                "",
                "The OCS charge is not expected to scale linearly with bytes because",
                "the configured tariff/quota logic is nonlinear. The paired claim is",
                "the observed increase under an identical packet workload.",
                "",
                "Claim boundary: three CCR-U/CCA-U exchanges are validated; this pair",
                "does not claim capture of CCR-I/T.",
                "",
            )
        ),
        encoding="utf-8",
    )
    checksum_paths = sorted(path for path in output.iterdir() if path.name != "SHA256SUMS")
    (output / "SHA256SUMS").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in checksum_paths),
        encoding="utf-8",
    )

    print("T3-1 paired live validation: PASS")
    print(
        f"usage {result['baseline_usage_sum']:,} -> "
        f"{result['attack_reported_usage_sum']:,} bytes (x5)"
    )
    print(
        f"OCS charge {result['baseline_charge_cents']} -> "
        f"{result['attack_charge_cents']} cents"
    )
    print(f"output: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PairError as error:
        print(f"ERROR: {error}")
        raise SystemExit(1) from error

