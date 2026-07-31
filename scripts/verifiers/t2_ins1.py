#!/usr/bin/env python3
"""Validate and finalize a paired clean-source T2-1 live reproduction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from t1_mod1 import application_flow, icmp_noise, workload
from t3_mod1 import (
    EXPECTED_COMMIT,
    PairError,
    accepted_pfcp_responses,
    charge,
    environment,
    packet_count,
    preflight,
    sha256,
    tshark_rows,
    verify_checksums,
)


TRACE_PATTERN = re.compile(r"primary\[(\d+)\] duplicate\[(\d+)\]")


def integer_values(text: str) -> list[int]:
    return [int(value, 0) for value in text.split(",") if value]


def established_urrs(directory: Path) -> set[int]:
    rows = tshark_rows(
        directory / "pfcp.pcap",
        "pfcp.msg_type == 50",
        ("pfcp.urr_id",),
    )
    values = {
        value
        for row in rows
        for value in integer_values(row[0])
    }
    if not values:
        raise PairError(f"missing established URRs in {directory}")
    return values


def pfcp_usage_by_urr(
    directory: Path,
    display_filter: str = "pfcp.volume_measurement.tovol",
) -> dict[int, list[tuple[int, int, int]]]:
    rows = tshark_rows(
        directory / "pfcp.pcap",
        display_filter,
        (
            "pfcp.urr_id",
            "pfcp.volume_measurement.tovol",
            "pfcp.volume_measurement.ulvol",
            "pfcp.volume_measurement.dlvol",
        ),
    )
    usage: dict[int, list[tuple[int, int, int]]] = {}
    for urr_text, total_text, uplink_text, downlink_text in rows:
        urrs = integer_values(urr_text)
        totals = integer_values(total_text)
        uplinks = integer_values(uplink_text)
        downlinks = integer_values(downlink_text)
        if not (len(urrs) == len(totals) == len(uplinks) == len(downlinks)):
            raise PairError(f"unaligned PFCP Usage Report fields in {directory}")
        for urr, total, uplink, downlink in zip(
            urrs, totals, uplinks, downlinks
        ):
            if total != uplink + downlink:
                raise PairError(f"invalid PFCP usage tuple in {directory}")
            usage.setdefault(urr, []).append((total, uplink, downlink))
    if not usage:
        raise PairError(f"missing PFCP usage in {directory}")
    return usage


def aggregate_streams(
    streams: dict[int, list[tuple[int, int, int]]]
) -> tuple[int, int, int]:
    rows = [row for stream in streams.values() for row in stream]
    return tuple(sum(row[index] for row in rows) for index in range(3))


def gy_update_aggregate(directory: Path) -> tuple[tuple[int, int, int], int]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1 && "
        "diameter.CC-Request-Type == 2",
        ("diameter.CC-Input-Octets", "diameter.CC-Output-Octets"),
    )
    values: list[tuple[int, int, int]] = []
    for input_text, output_text in rows:
        uplink = sum(integer_values(input_text))
        downlink = sum(integer_values(output_text))
        values.append((uplink + downlink, uplink, downlink))
    if not values:
        raise PairError(f"missing Gy CCR-U usage in {directory}")
    return (
        tuple(sum(row[index] for row in values) for index in range(3)),
        len(values),
    )


def successful_cca(directory: Path) -> tuple[int, int]:
    request_rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1",
        ("diameter.CC-Request-Type",),
    )
    answer_rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 0",
        ("diameter.Result-Code",),
    )
    successful = sum(
        1 for row in answer_rows if "2001" in row[0].split(",")
    )
    return len(request_rows), successful


def trace_urrs(directory: Path) -> tuple[int, int, int]:
    text = (directory / "duplicate_urr_trace.txt").read_text(encoding="utf-8")
    values = [
        tuple(int(value) for value in match.groups())
        for match in TRACE_PATTERN.finditer(text)
    ]
    if not values:
        raise PairError("attack duplicate-URR trace is empty")
    distinct = set(values)
    if len(distinct) != 1:
        raise PairError(f"inconsistent duplicate-URR trace: {values}")
    primary, duplicate = next(iter(distinct))
    if primary == duplicate:
        raise PairError("primary and duplicate URR IDs are equal")
    return primary, duplicate, len(values)


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
        if values.get("case_id") != "T2-1" or checked.get("case_id") != "T2-1":
            raise PairError(f"{directory}: case identity mismatch")
        if values.get("open5gs_commit") != EXPECTED_COMMIT:
            raise PairError(f"{directory}: Open5GS commit mismatch")
        if values.get("kernel") != "6.17.0-40-generic":
            raise PairError(f"{directory}: kernel mismatch")

    baseline_established = established_urrs(baseline)
    attack_established = established_urrs(attack)
    baseline_pfcp = pfcp_usage_by_urr(baseline)
    attack_pfcp = pfcp_usage_by_urr(attack)
    baseline_pfcp_updates = pfcp_usage_by_urr(
        baseline,
        "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
    )
    attack_pfcp_updates = pfcp_usage_by_urr(
        attack,
        "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
    )
    baseline_pfcp_aggregate = aggregate_streams(baseline_pfcp)
    attack_pfcp_aggregate = aggregate_streams(attack_pfcp)
    baseline_update_aggregate = aggregate_streams(baseline_pfcp_updates)
    attack_update_aggregate = aggregate_streams(attack_pfcp_updates)
    baseline_gy_aggregate, baseline_gy_count = gy_update_aggregate(baseline)
    attack_gy_aggregate, attack_gy_count = gy_update_aggregate(attack)
    primary_urr, duplicate_urr, trace_count = trace_urrs(attack)
    baseline_charge = charge(baseline)
    attack_charge = charge(attack)
    baseline_requests, baseline_successful = successful_cca(baseline)
    attack_requests, attack_successful = successful_cca(attack)
    baseline_packets = packet_count(baseline / "gtpu.pcap")
    attack_packets = packet_count(attack / "gtpu.pcap")
    baseline_app_packets, baseline_app_bytes = application_flow(baseline)
    attack_app_packets, attack_app_bytes = application_flow(attack)
    baseline_icmp_count, baseline_icmp_bytes = icmp_noise(baseline)
    attack_icmp_count, attack_icmp_bytes = icmp_noise(attack)
    baseline_workload = workload(baseline)
    attack_workload = workload(attack)
    expected_workload = {
        "workload_id": "W3_EXACT_1MIB_UL_3MIB_DL",
        "ul_application_bytes": 1_048_576,
        "dl_application_bytes": 3_145_728,
        "total_application_bytes": 4_194_304,
        "datagram_payload_bytes": 1024,
    }
    attack_streams = list(attack_pfcp.values())

    relations = {
        "identical_exact_workload":
            baseline_workload == attack_workload == expected_workload,
        "identical_application_gtpu_flow":
            baseline_app_packets == attack_app_packets == 4096
            and baseline_app_bytes == attack_app_bytes == 4_194_304,
        "one_baseline_urr": len(baseline_established) == len(baseline_pfcp) == 1,
        "two_attack_urrs":
            len(attack_established) == len(attack_pfcp) == 2
            and {primary_urr, duplicate_urr} == attack_established,
        "producer_trace_distinct_urrs":
            primary_urr != duplicate_urr and trace_count >= 1,
        "duplicate_pfcp_streams_equal":
            len(attack_streams) == 2 and attack_streams[0] == attack_streams[1],
        "baseline_pfcp_updates_equal_gy":
            baseline_update_aggregate == baseline_gy_aggregate,
        "attack_pfcp_updates_equal_gy":
            attack_update_aggregate == attack_gy_aggregate,
        "attack_pfcp_responses_accepted":
            accepted_pfcp_responses(attack)
            == sum(len(stream) for stream in attack_pfcp_updates.values()),
        "all_cca_accepted":
            baseline_requests == baseline_successful
            and attack_requests == attack_successful
            and attack_requests > 0,
        "backend_charge_increased":
            attack_charge["charged_cents"] > baseline_charge["charged_cents"],
    }
    failed_relations = [name for name, passed in relations.items() if not passed]
    if failed_relations:
        raise PairError(f"failed semantic relations: {failed_relations}")

    result = {
        "schema_version": "1.0",
        "run_id": f"paired_{baseline.name}__{attack.name}",
        "audit_id": "T2-A22",
        "legacy_threat_id": "T2-1",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "workload": expected_workload["workload_id"],
        "kernel": "6.17.0-40-generic",
        "open5gs_commit": EXPECTED_COMMIT,
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
        "baseline_urr_count": len(baseline_established),
        "attack_urr_count": len(attack_established),
        "reports_per_attack_urr": len(attack_streams[0]),
        "pfcp_usage_sum": {
            "baseline": baseline_pfcp_aggregate[0],
            "attack": attack_pfcp_aggregate[0],
        },
        "gy_usage_sum": {
            "baseline": baseline_gy_aggregate[0],
            "attack": attack_gy_aggregate[0],
        },
        "gy_usage_request_count": {
            "baseline": baseline_gy_count,
            "attack": attack_gy_count,
        },
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents":
            attack_charge["charged_cents"] - baseline_charge["charged_cents"],
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
            "This pair validates duplicate attribution for one exact application "
            "flow through the observed PFCP Session Report to CCR-U/CCA-U path "
            "in the documented Open5GS/Gy/SigScale testbed. Environmental ICMP "
            "is counted separately. CCR-I/T and terminal PFCP-to-Gy propagation "
            "are not claimed, nor is universal duplicate-URR pricing."
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
                "# T2-1 Paired Live Validation",
                "",
                "Result: `E2E PASS`.",
                "",
                f"- Kernel: `{result['kernel']}`",
                "- Exact application workload: `1 MiB UL + 3 MiB DL` per run",
                f"- Identical application GTP-U: `{baseline_app_packets:,}` packets / "
                f"`{baseline_app_bytes:,}` payload bytes per run",
                "- Installed accounting scope: `1` baseline URR → `2` attack URRs",
                f"- PFCP-update/Gy usage: `{baseline_update_aggregate[0]:,}` "
                f"baseline → `{attack_update_aggregate[0]:,}` attack bytes",
                f"- OCS charge: `{result['baseline_charge_cents']}¢` baseline → "
                f"`{result['attack_charge_cents']}¢` attack",
                f"- Charge delta: `+{result['charge_delta_cents']}¢`",
                "",
                "Claim boundary: the result is specific to the documented",
                "Open5GS/Gy/SigScale testbed. Environmental ICMP is counted",
                "separately. Only PFCP Session Report→CCR-U/CCA-U is claimed;",
                "CCR-I/T, terminal PFCP-to-Gy, and universal pricing are not.",
                "",
            )
        ),
        encoding="utf-8",
    )
    checksum_paths = sorted(
        path for path in output.iterdir() if path.name != "SHA256SUMS"
    )
    (output / "SHA256SUMS").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in checksum_paths),
        encoding="utf-8",
    )

    print("T2-1 paired live validation: PASS")
    print(
        f"charge {result['baseline_charge_cents']} -> "
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
