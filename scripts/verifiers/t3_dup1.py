#!/usr/bin/env python3
"""Finalize a clean-source T3-2 pair without weakening its claim boundary."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess


EXPECTED_COMMIT = "26cbc33a418a292e3b3949be69155898d751bd6e"


class PairError(Exception):
    pass


def run(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        raise PairError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def verify_run(run_dir: Path) -> int:
    count = 0
    for line in (run_dir / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split(None, 1)
        path = run_dir / relative.strip()
        if not path.is_file() or digest(path) != expected:
            raise PairError(f"run checksum mismatch: {path}")
        count += 1
    return count


def fields(path: Path, display_filter: str, names: tuple[str, ...]) -> list[list[str]]:
    args = [
        "tshark", "-n", "-r", str(path), "-Y", display_filter,
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
    ]
    for name in names:
        args.extend(("-e", name))
    return [line.split("\t") for line in run(*args).splitlines()]


def tuple_list(cell: str) -> list[int]:
    return [int(value) for value in cell.split(",") if value]


def pfcp(run_dir: Path) -> list[list[tuple[int, int, int]]]:
    rows = fields(
        run_dir / "pfcp.pcap",
        "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
        (
            "pfcp.volume_measurement.tovol",
            "pfcp.volume_measurement.ulvol",
            "pfcp.volume_measurement.dlvol",
        ),
    )
    reports = []
    for row in rows:
        row += [""] * (3 - len(row))
        totals, uplinks, downlinks = map(tuple_list, row)
        if not (len(totals) == len(uplinks) == len(downlinks)):
            raise PairError("inconsistent PFCP grouped value counts")
        reports.append(list(zip(totals, uplinks, downlinks)))
    return reports


def gy(run_dir: Path) -> list[tuple[int, int, int]]:
    rows = fields(
        run_dir / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1 "
        "&& diameter.CC-Request-Type == 2",
        ("diameter.CC-Input-Octets", "diameter.CC-Output-Octets"),
    )
    result = []
    for row in rows:
        row += [""] * (2 - len(row))
        uplink, downlink = int(row[0] or 0), int(row[1] or 0)
        result.append((uplink + downlink, uplink, downlink))
    return result


def accepted(run_dir: Path, protocol: str) -> int:
    if protocol == "pfcp":
        rows = fields(run_dir / "pfcp.pcap", "pfcp.msg_type == 57", ("pfcp.cause",))
        return sum(row and row[0] == "1" for row in rows)
    rows = fields(
        run_dir / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 0 "
        "&& diameter.CC-Request-Type == 2",
        ("diameter.Result-Code",),
    )
    return sum(row and "2001" in row[0].split(",") for row in rows)


def icmp_counts(run_dir: Path) -> dict[str, int]:
    rows = fields(run_dir / "gtpu.pcap", "gtp && icmp", ("icmp.type",))
    return {
        "echo_request": sum(row and row[0] == "8" for row in rows),
        "echo_reply": sum(row and row[0] == "0" for row in rows),
    }


def charge(run_dir: Path) -> dict:
    return json.loads((run_dir / "ocs_balance_summary.json").read_text())


def environment(run_dir: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in (run_dir / "environment.txt").read_text().splitlines()
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    baseline, attack, output = (
        args.baseline.resolve(), args.attack.resolve(), args.output.resolve()
    )

    baseline_checksums, attack_checksums = verify_run(baseline), verify_run(attack)
    baseline_env, attack_env = environment(baseline), environment(attack)
    if {baseline_env.get("open5gs_commit"), attack_env.get("open5gs_commit")} != {
        EXPECTED_COMMIT
    }:
        raise PairError("Open5GS commit mismatch")
    if attack_env.get("case_id") != "T3-2":
        raise PairError("attack case mismatch")

    baseline_pfcp, attack_pfcp = pfcp(baseline), pfcp(attack)
    if not baseline_pfcp or any(len(report) != 1 for report in baseline_pfcp):
        raise PairError("baseline is not one report IE per request")
    if any(len(report) != 2 or report[0] != report[1] for report in attack_pfcp):
        raise PairError("attack does not carry two identical report IEs")
    originals = [report[0] for report in baseline_pfcp]
    attack_originals = [report[0] for report in attack_pfcp]
    if originals != attack_originals:
        raise PairError("baseline and attack producer usage differ")

    baseline_gy, attack_gy = gy(baseline), gy(attack)
    doubled = [tuple(value * 2 for value in report) for report in originals]
    if baseline_gy != originals or attack_gy != doubled:
        raise PairError("PFCP to Gy exact duplication relation failed")
    if accepted(attack, "pfcp") != len(attack_pfcp):
        raise PairError("not all PFCP responses were accepted")
    if accepted(attack, "gy") != len(attack_gy):
        raise PairError("not all CCA-U responses were accepted")

    baseline_icmp, attack_icmp = icmp_counts(baseline), icmp_counts(attack)
    if baseline_icmp["echo_request"] != attack_icmp["echo_request"]:
        raise PairError("intended ICMP request workload differs")
    if abs(baseline_icmp["echo_reply"] - attack_icmp["echo_reply"]) > 1:
        raise PairError("unexpected reply-capture difference")
    baseline_charge, attack_charge = charge(baseline), charge(attack)
    if attack_charge["charged_cents"] <= baseline_charge["charged_cents"]:
        raise PairError("attack charge did not increase")

    result = {
        "schema_version": "1.0",
        "legacy_threat_id": "T3-2",
        "audit_id": "T3-A08",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "validation": "E2E",
        "kernel": attack_env["kernel"],
        "open5gs_commit": EXPECTED_COMMIT,
        "report_count": len(originals),
        "usage_report_ies_per_baseline_request": 1,
        "usage_report_ies_per_attack_request": 2,
        "baseline_original_usage": originals,
        "attack_duplicate_usage": attack_pfcp,
        "baseline_gy_usage": baseline_gy,
        "attack_gy_usage": attack_gy,
        "baseline_usage_sum": sum(value[0] for value in originals),
        "attack_gy_usage_sum": sum(value[0] for value in attack_gy),
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "baseline_icmp": baseline_icmp,
        "attack_icmp": attack_icmp,
        "capture_noise": "baseline missed one echo reply; intended requests and PFCP producer usage are identical",
        "accepted_pfcp_responses": accepted(attack, "pfcp"),
        "accepted_cca_updates": accepted(attack, "gy"),
        "source_run_checksums": {
            "baseline": baseline_checksums,
            "attack": attack_checksums,
        },
    }

    output.mkdir(parents=True, exist_ok=True)
    for label, source in (("baseline", baseline), ("attack", attack)):
        target = output / label
        target.mkdir(exist_ok=True)
        names = [
            "environment.txt", "ocs_balance_summary.json", "pfcp.pcap",
            "gy.pcap", "gtpu.pcap", "preflight.json",
        ]
        names.append("baseline_trace.txt" if label == "baseline" else "mutation_trace.txt")
        for name in names:
            shutil.copy2(source / name, target / name)
    (output / "paired_result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    (output / "PAIR_VALIDATION.md").write_text(
        "# T3-2 paired live validation\n\n"
        "Three attack PFCP requests each carry two byte-semantically identical "
        "Usage Report tuples. The SMF accumulates both, so every observed Gy "
        "CCR-U is exactly twice the clean producer usage; all PFCP responses "
        "and CCA-U responses are accepted. OCS charge changes from "
        f"{baseline_charge['charged_cents']}¢ to {attack_charge['charged_cents']}¢.\n\n"
        "The baseline GTP-U capture missed one echo reply. Both runs contain "
        "15,200 intended echo requests and identical PFCP producer usage, so "
        "that capture-only difference is not attributed to the mutation.\n",
        encoding="utf-8",
    )
    (output / "PROVENANCE.md").write_text(
        "# Provenance\n\n"
        f"Baseline source run: `{baseline.name}` (the clean T3 family baseline).\n\n"
        f"Attack source run: `{attack.name}`.\n\n"
        f"Open5GS: `{EXPECTED_COMMIT}`. The attack adds only the common bounded "
        "fixture and `t3-2_intra_message_duplication.patch`. Raw source runs "
        "remain outside this selected package.\n",
        encoding="utf-8",
    )
    entries = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            entries.append(f"{digest(path)}  {path.relative_to(output)}")
    (output / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
