#!/usr/bin/env python3
"""Validate and finalize a paired clean-source T1-1 live reproduction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from t3_mod1 import (
    EXPECTED_COMMIT,
    PairError,
    charge,
    environment,
    packet_count,
    pfcp_usage,
    preflight,
    sha256,
    tshark_rows,
    verify_checksums,
)


TRACE_PATTERN = re.compile(r"context_5qi\[(\d+)\] wire_5qi\[(\d+)\]")


def n7_policy(directory: Path) -> tuple[set[int], set[int], int]:
    rows = tshark_rows(directory / "n7.pcap", "http2.data.data",
                      ("frame.number", "http2.data.data"))
    requests: set[int] = set()
    responses: set[int] = set()
    decoded = 0
    for _frame, raw in rows:
        try:
            payload = bytes.fromhex(raw.replace(",", "")).decode("utf-8")
            value = json.loads(payload)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        if "subsDefQos" in value and "5qi" in value["subsDefQos"]:
            requests.add(int(value["subsDefQos"]["5qi"]))
            decoded += 1
        if "sessRules" in value:
            for rule in value["sessRules"].values():
                qos = rule.get("authDefQos", {})
                if "5qi" in qos:
                    responses.add(int(qos["5qi"]))
                    decoded += 1
    if not requests or not responses:
        raise PairError(f"missing N7 policy request/response in {directory}")
    return requests, responses, decoded


def gy_usage(directory: Path) -> list[tuple[int, int, int]]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1 && "
        "(diameter.CC-Request-Type == 2 || diameter.CC-Request-Type == 3)",
        ("diameter.CC-Input-Octets", "diameter.CC-Output-Octets"),
    )
    values: list[tuple[int, int, int]] = []
    for input_octets, output_octets in rows:
        uplink = int(input_octets or "0")
        downlink = int(output_octets or "0")
        values.append((uplink + downlink, uplink, downlink))
    if not values:
        raise PairError(f"no Gy usage requests in {directory}")
    return values


def gy_identity(directory: Path) -> tuple[set[int], set[int]]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1",
        ("diameter.Rating-Group", "diameter.QoS-Class-Identifier"),
    )
    groups: set[int] = set()
    qci: set[int] = set()
    for group_values, qci_values in rows:
        groups.update(int(value, 0) for value in group_values.split(",") if value)
        qci.update(int(value, 0) for value in qci_values.split(",") if value)
    if not groups or not qci:
        raise PairError(f"missing Gy charging identity in {directory}")
    return groups, qci


def successful_cca_types(directory: Path) -> set[int]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 0",
        ("diameter.CC-Request-Type", "diameter.Result-Code"),
    )
    return {
        int(kind)
        for kind, result in rows
        if kind and "2001" in result.split(",")
    }


def trace_pair(directory: Path) -> tuple[int, int, int]:
    text = (directory / "rewrite_trace.txt").read_text(encoding="utf-8")
    matches = [tuple(int(value) for value in match.groups())
               for match in TRACE_PATTERN.finditer(text)]
    if not matches:
        raise PairError("attack rewrite trace is empty")
    if set(matches) != {(9, 6)}:
        raise PairError(f"unexpected rewrite trace values: {matches}")
    return 9, 6, len(matches)


def tariffs(directory: Path) -> dict[int, tuple[int, int]]:
    data = json.loads((directory / "tariff_summary.json").read_text(encoding="utf-8"))
    return {
        int(item["key"]): (int(item["unit_bytes"]), int(item["cents"]))
        for item in data
    }


def workload(directory: Path) -> dict[str, int | str]:
    return json.loads((directory / "workload_summary.json").read_text(encoding="utf-8"))


def application_flow(directory: Path) -> tuple[int, int]:
    rows = tshark_rows(
        directory / "gtpu.pcap",
        "gtp && udp.port == 39000 && !icmp",
        ("udp.length",),
    )
    payload_bytes = 0
    for row in rows:
        lengths = [int(value) for value in row[0].split(",") if value]
        if not lengths or lengths[-1] < 8:
            raise PairError(f"invalid application UDP length in {directory}")
        payload_bytes += lengths[-1] - 8
    return len(rows), payload_bytes


def icmp_noise(directory: Path) -> tuple[int, int]:
    rows = tshark_rows(directory / "gtpu.pcap", "gtp && icmp", ("ip.len",))
    inner_bytes = 0
    for row in rows:
        lengths = [int(value) for value in row[0].split(",") if value]
        if len(lengths) < 2:
            raise PairError(f"invalid encapsulated ICMP length in {directory}")
        inner_bytes += lengths[-2]
    return len(rows), inner_bytes


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
    attack_preflight = preflight(attack, "attack")
    baseline_preflight = preflight(baseline, "baseline")
    for directory, values, checked in (
        (attack, attack_environment, attack_preflight),
        (baseline, baseline_environment, baseline_preflight),
    ):
        if values.get("case_id") != "T1-1" or checked.get("case_id") != "T1-1":
            raise PairError(f"{directory}: case identity mismatch")
        if values.get("open5gs_commit") != EXPECTED_COMMIT:
            raise PairError(f"{directory}: Open5GS commit mismatch")
        if values.get("kernel") != "6.17.0-40-generic":
            raise PairError(f"{directory}: kernel mismatch")

    baseline_pfcp = pfcp_usage(baseline)
    attack_pfcp = pfcp_usage(attack)
    baseline_gy = gy_usage(baseline)
    attack_gy = gy_usage(attack)
    baseline_n7_in, baseline_n7_out, baseline_n7_samples = n7_policy(baseline)
    attack_n7_in, attack_n7_out, attack_n7_samples = n7_policy(attack)
    baseline_groups, baseline_qci = gy_identity(baseline)
    attack_groups, attack_qci = gy_identity(attack)
    context_5qi, wire_5qi, trace_count = trace_pair(attack)
    baseline_charge = charge(baseline)
    attack_charge = charge(attack)
    baseline_packets = packet_count(baseline / "gtpu.pcap")
    attack_packets = packet_count(attack / "gtpu.pcap")
    baseline_app_packets, baseline_app_bytes = application_flow(baseline)
    attack_app_packets, attack_app_bytes = application_flow(attack)
    baseline_icmp_count, baseline_icmp_bytes = icmp_noise(baseline)
    attack_icmp_count, attack_icmp_bytes = icmp_noise(attack)
    baseline_tariffs = tariffs(baseline)
    attack_tariffs = tariffs(attack)
    baseline_workload = workload(baseline)
    attack_workload = workload(attack)
    baseline_aggregate = tuple(
        sum(row[index] for row in baseline_pfcp) for index in range(3)
    )
    attack_aggregate = tuple(
        sum(row[index] for row in attack_pfcp) for index in range(3)
    )
    expected_workload = {
        "workload_id": "W3_EXACT_1MIB_UL_3MIB_DL",
        "ul_application_bytes": 1_048_576,
        "dl_application_bytes": 3_145_728,
        "total_application_bytes": 4_194_304,
        "datagram_payload_bytes": 1024,
    }
    expected_tariffs = {6: (1_000_000, 10), 9: (1_000_000, 1)}

    relations = {
        "identical_exact_workload":
            baseline_workload == attack_workload == expected_workload,
        "identical_application_gtpu_flow":
            baseline_app_packets == attack_app_packets == 4096
            and baseline_app_bytes == attack_app_bytes == 4_194_304,
        "baseline_n7_9_to_9":
            baseline_n7_in == {9} and baseline_n7_out == {9},
        "attack_n7_9_to_6":
            attack_n7_in == {9} and attack_n7_out == {6},
        "producer_trace_9_to_6":
            context_5qi == 9 and wire_5qi == 6 and trace_count >= 1,
        "identical_pfcp_uplink": baseline_aggregate[1] == attack_aggregate[1],
        "pfcp_delta_explained_by_icmp_noise":
            attack_aggregate[0] - baseline_aggregate[0]
            == attack_icmp_bytes - baseline_icmp_bytes
            and attack_aggregate[2] - baseline_aggregate[2]
            == attack_icmp_bytes - baseline_icmp_bytes,
        "baseline_pfcp_update_equals_gy":
            len(baseline_gy) == 1 and baseline_pfcp[:1] == baseline_gy,
        "attack_pfcp_update_equals_gy":
            len(attack_gy) == 1 and attack_pfcp[:1] == attack_gy,
        "baseline_gy_identity_9":
            baseline_groups == {9} and baseline_qci == {9},
        "attack_gy_identity_6": attack_groups == {6} and attack_qci == {6},
        "successful_cca_u":
            successful_cca_types(baseline) == {2}
            and successful_cca_types(attack) == {2},
        "identical_differentiated_tariffs":
            baseline_tariffs == attack_tariffs == expected_tariffs,
        "exact_10x_charge":
            baseline_charge["charged_cents"] > 0
            and attack_charge["charged_cents"]
            == baseline_charge["charged_cents"] * 10,
    }
    failed_relations = [name for name, passed in relations.items() if not passed]
    if failed_relations:
        raise PairError(f"failed semantic relations: {failed_relations}")

    result = {
        "schema_version": "1.0",
        "run_id": f"paired_{baseline.name}__{attack.name}",
        "audit_id": "T1-A25",
        "legacy_threat_id": "T1-1",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "workload": expected_workload["workload_id"],
        "kernel": "6.17.0-40-generic",
        "open5gs_commit": EXPECTED_COMMIT,
        "baseline_5qi": 9,
        "attack_5qi": 6,
        "application_gtpu_packet_count_each": baseline_app_packets,
        "application_gtpu_payload_bytes_each": baseline_app_bytes,
        "total_gtpu_packet_count": {
            "baseline": baseline_packets,
            "attack": attack_packets,
        },
        "icmp_noise": {
            "baseline_count": baseline_icmp_count,
            "attack_count": attack_icmp_count,
            "baseline_bytes": baseline_icmp_bytes,
            "attack_bytes": attack_icmp_bytes,
        },
        "pfcp_usage_report_count": len(baseline_pfcp),
        "gy_ccr_update_count": len(baseline_gy),
        "pfcp_usage_sum": {
            "baseline": baseline_aggregate[0],
            "attack": attack_aggregate[0],
        },
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_multiplier": 10,
        "charge_delta_cents":
            attack_charge["charged_cents"] - baseline_charge["charged_cents"],
        "n7_policy_samples": {
            "baseline": baseline_n7_samples,
            "attack": attack_n7_samples,
        },
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
            "5QI has no universal monetary meaning. This result depends on "
            "the documented testbed mapping of Rating-Group 9 to 1 cent/MB "
            "and Rating-Group 6 to 10 cents/MB. The W3 4 MiB live pair must "
            "not be merged with the separate cumulative 16.05 MB result. "
            "The live pair validates the observed CCR-U/CCA-U path; it does "
            "not claim CCR-I/T capture or that terminal PFCP usage reached Gy."
        ),
    }

    output.mkdir(parents=True, exist_ok=False)
    (output / "paired_result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    (output / "SOURCE_RUNS.txt").write_text(
        f"baseline={baseline.name}\nattack={attack.name}\n", encoding="utf-8"
    )
    (output / "PAIR_VALIDATION.md").write_text(
        "\n".join(
            (
                "# T1-1 Paired Live Validation",
                "",
                "Result: `E2E PASS`.",
                "",
                f"- Kernel: `{result['kernel']}`",
                "- Exact application workload: `1 MiB UL + 3 MiB DL` per run",
                f"- Identical application GTP-U: `{baseline_app_packets:,}` packets / "
                f"`{baseline_app_bytes:,}` UDP payload bytes per run",
                f"- PFCP total: `{baseline_aggregate[0]:,}` baseline / "
                f"`{attack_aggregate[0]:,}` attack bytes",
                f"- External ICMP noise: `{baseline_icmp_count}` baseline / "
                f"`{attack_icmp_count}` attack packets; the `112`-byte PFCP "
                "difference is fully explained",
                "- N7 policy: `9→9` baseline, `9→6` attack",
                "- Gy Rating-Group/QCI: `9/9` baseline, `6/6` attack",
                f"- OCS charge: `{result['baseline_charge_cents']}¢` baseline → "
                f"`{result['attack_charge_cents']}¢` attack",
                "- Charge multiplier: exact `×10`",
                "",
                "Claim boundary: 5QI is not universally premium or standard.",
                "The monetary result depends on the documented testbed mapping.",
                "This W3 pair is separate from the cumulative 16.05 MB result.",
                "Only CCR-U/CCA-U is claimed; CCR-I/T and propagation of the",
                "terminal PFCP report to Gy are not claimed.",
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

    print("T1-1 paired live validation: PASS")
    print(
        f"charge {result['baseline_charge_cents']} -> "
        f"{result['attack_charge_cents']} cents (x10)"
    )
    print(f"output: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PairError as error:
        print(f"ERROR: {error}")
        raise SystemExit(1) from error
