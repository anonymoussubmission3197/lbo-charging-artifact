#!/usr/bin/env python3
"""Validate and finalize a paired clean-source T4-1 Gy reproduction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from t3_mod1 import (
    EXPECTED_COMMIT,
    PairError,
    accepted_cca_updates,
    accepted_pfcp_responses,
    charge,
    environment,
    packet_count,
    pfcp_usage,
    preflight,
    sha256,
    tshark_rows,
    verify_checksums,
)


TRACE_PATTERN = re.compile(
    r"request_type\[(\d+)\] factor\[(\d+)\] "
    r"actual_ul\[(\d+)\] reported_ul\[(\d+)\]"
)


def gy_usage(directory: Path) -> list[tuple[int, int, int]]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1 "
        "&& diameter.CC-Request-Type == 2",
        ("diameter.CC-Input-Octets", "diameter.CC-Output-Octets"),
    )
    values: list[tuple[int, int, int]] = []
    for input_octets, output_octets in rows:
        uplink = int(input_octets or "0")
        downlink = int(output_octets or "0")
        values.append((uplink + downlink, uplink, downlink))
    if not values:
        raise PairError(f"no Gy CCR-U usage in {directory}")
    return values


def trace_usage(directory: Path) -> tuple[list[int], list[int]]:
    text = (directory / "inflation_trace.txt").read_text(encoding="utf-8")
    matches = [
        tuple(int(value) for value in match.groups())
        for match in TRACE_PATTERN.finditer(text)
    ]
    updates = [row for row in matches if row[0] == 2]
    if not updates:
        raise PairError("attack inflation trace has no CCR-U entries")
    if any(factor != 4 or reported != actual * 4
           for _kind, factor, actual, reported in updates):
        raise PairError("producer trace does not satisfy exact x4 UL mutation")
    return (
        [actual for _kind, _factor, actual, _reported in updates],
        [reported for _kind, _factor, _actual, reported in updates],
    )


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
        if values.get("case_id") != "T4-1" or checked.get("case_id") != "T4-1":
            raise PairError(f"{directory}: case identity mismatch")
        if values.get("implementation_profile") != "Gy-semantic-analogue":
            raise PairError(f"{directory}: implementation profile mismatch")
        if values.get("open5gs_commit") != EXPECTED_COMMIT:
            raise PairError(f"{directory}: Open5GS commit mismatch")
        if values.get("kernel") != "6.17.0-40-generic":
            raise PairError(f"{directory}: kernel mismatch")

    baseline_pfcp = pfcp_usage(baseline)
    attack_pfcp = pfcp_usage(attack)
    baseline_gy = gy_usage(baseline)
    attack_gy = gy_usage(attack)
    trace_actual_ul, trace_reported_ul = trace_usage(attack)
    baseline_charge = charge(baseline)
    attack_charge = charge(attack)
    baseline_packets = packet_count(baseline / "gtpu.pcap")
    attack_packets = packet_count(attack / "gtpu.pcap")

    baseline_ul = [uplink for _total, uplink, _downlink in baseline_pfcp]
    attack_ul = [uplink for _total, uplink, _downlink in attack_pfcp]
    attack_dl = [downlink for _total, _uplink, downlink in attack_pfcp]
    attack_gy_ul = [uplink for _total, uplink, _downlink in attack_gy]
    attack_gy_dl = [downlink for _total, _uplink, downlink in attack_gy]
    baseline_aggregate = tuple(
        sum(row[index] for row in baseline_pfcp) for index in range(3)
    )
    attack_aggregate = tuple(
        sum(row[index] for row in attack_pfcp) for index in range(3)
    )

    relations = {
        "identical_gtpu_packet_count":
            baseline_packets == attack_packets and baseline_packets > 0,
        "identical_report_count":
            len(baseline_pfcp) == len(attack_pfcp) and len(attack_pfcp) > 0,
        "baseline_pfcp_equals_gy": baseline_pfcp == baseline_gy,
        "baseline_pfcp_aggregate_equals_attack": baseline_aggregate == attack_aggregate,
        "attack_pfcp_equals_trace_actual_ul": attack_ul == trace_actual_ul,
        "attack_trace_exact_x4": trace_reported_ul
            == [value * 4 for value in trace_actual_ul],
        "attack_trace_equals_gy_input": trace_reported_ul == attack_gy_ul,
        "attack_downlink_unchanged": attack_dl == attack_gy_dl,
        "pfcp_reports_accepted":
            accepted_pfcp_responses(attack) == len(attack_pfcp),
        "cca_updates_accepted":
            accepted_cca_updates(attack) == len(attack_gy),
        "backend_charge_increased":
            attack_charge["charged_cents"] > baseline_charge["charged_cents"],
    }
    failed_relations = [name for name, passed in relations.items() if not passed]
    if failed_relations:
        raise PairError(f"failed semantic relations: {failed_relations}")

    result = {
        "schema_version": "1.0",
        "run_id": f"paired_{baseline.name}__{attack.name}",
        "audit_id": "T4G-A17",
        "legacy_threat_id": "T4-1",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "implementation_profile": "Gy-semantic-analogue",
        "kernel": "6.17.0-40-generic",
        "open5gs_commit": EXPECTED_COMMIT,
        "mutation_factor": 4,
        "mutated_field": "CC-Input-Octets",
        "gtpu_packet_count_each": baseline_packets,
        "report_count": len(attack_pfcp),
        "baseline_pfcp_usage": baseline_pfcp,
        "attack_pfcp_usage": attack_pfcp,
        "attack_actual_ul": trace_actual_ul,
        "attack_reported_ul": trace_reported_ul,
        "baseline_actual_ul_sum": sum(baseline_ul),
        "attack_reported_ul_sum": sum(trace_reported_ul),
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
            "This paired live run validates accepted Gy CCR-U/CCA-U exchanges "
            "in the Open5GS/SigScale prototype. It does not claim native "
            "N40/Nchf CHF acceptance or capture of CCR-I/T."
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
                "# T4-1 Paired Live Validation",
                "",
                "Result: `E2E PASS` for the Gy semantic analogue.",
                "",
                f"- Kernel: `{result['kernel']}`",
                f"- Identical GTP-U packet count: `{baseline_packets:,}` per run",
                f"- Baseline actual UL: `{result['baseline_actual_ul_sum']:,}` bytes",
                f"- Attack Gy-reported UL: `{result['attack_reported_ul_sum']:,}` bytes",
                f"- Mutation: exact `×4` for all `{result['report_count']}` CCR-U reports",
                f"- OCS charge: `{result['baseline_charge_cents']}¢` baseline → "
                f"`{result['attack_charge_cents']}¢` attack",
                f"- Charge delta: `+{result['charge_delta_cents']}¢`",
                "",
                "The monetary charge is not expected to scale exactly with bytes",
                "because tariff units and quota behavior are nonlinear.",
                "",
                "Claim boundary: this is an Open5GS/SigScale Gy result. Native",
                "N40/Nchf CHF acceptance and CCR-I/T capture are not claimed.",
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

    print("T4-1 paired live validation: PASS (Gy semantic analogue)")
    print(
        f"UL usage {result['baseline_actual_ul_sum']:,} -> "
        f"{result['attack_reported_ul_sum']:,} bytes (x4)"
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
