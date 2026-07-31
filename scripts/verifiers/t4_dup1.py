#!/usr/bin/env python3
"""Finalize a clean-source T4-2 intra-CCR MSCC/USU duplication pair."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from t3_mod1 import (
    PairError,
    accepted_pfcp_responses,
    charge,
    environment,
    packet_count,
    pfcp_usage,
    preflight,
    tshark_rows,
    verify_checksums,
)


EXPECTED_COMMIT = "26cbc33a418a292e3b3949be69155898d751bd6e"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def integer_list(cell: str) -> list[int]:
    return [int(value) for value in cell.split(",") if value]


def gy_usage_groups(directory: Path) -> list[list[tuple[int, int, int]]]:
    """Return all Used-Service-Unit tuples grouped by CCR-Update."""
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1 "
        "&& diameter.CC-Request-Type == 2",
        ("diameter.CC-Input-Octets", "diameter.CC-Output-Octets"),
    )
    groups: list[list[tuple[int, int, int]]] = []
    for input_cell, output_cell in rows:
        inputs = integer_list(input_cell)
        outputs = integer_list(output_cell)
        if not inputs or len(inputs) != len(outputs):
            raise PairError("inconsistent Gy Used-Service-Unit tuple counts")
        groups.append([
            (uplink + downlink, uplink, downlink)
            for uplink, downlink in zip(inputs, outputs)
        ])
    if not groups:
        raise PairError(f"no Gy CCR-U usage in {directory}")
    return groups


def cca_result_groups(directory: Path) -> list[list[int]]:
    """Return top-level and per-MSCC result codes grouped by CCA-Update."""
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 0 "
        "&& diameter.CC-Request-Type == 2",
        ("diameter.Result-Code",),
    )
    return [integer_list(row[0]) for row in rows]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    baseline, attack, output = (
        args.baseline.resolve(), args.attack.resolve(), args.output.resolve()
    )

    baseline_checksum_count = verify_checksums(baseline)
    attack_checksum_count = verify_checksums(attack)
    baseline_environment = environment(baseline)
    attack_environment = environment(attack)
    baseline_preflight = preflight(baseline, "baseline")
    attack_preflight = preflight(attack, "attack")
    if {
        baseline_environment.get("open5gs_commit"),
        attack_environment.get("open5gs_commit"),
    } != {EXPECTED_COMMIT}:
        raise PairError("Open5GS commit mismatch")
    if (
        baseline_environment.get("case_id") != "T4-1"
        or baseline_preflight.get("case_id") != "T4-1"
        or attack_environment.get("case_id") != "T4-2"
        or attack_preflight.get("case_id") != "T4-2"
    ):
        raise PairError("baseline/attack case identity mismatch")
    if (
        baseline_environment.get("implementation_profile")
        != "Gy-semantic-analogue"
        or attack_environment.get("implementation_profile")
        != "Gy-semantic-analogue"
    ):
        raise PairError("implementation profile mismatch")

    baseline_pfcp = pfcp_usage(baseline)
    attack_pfcp = pfcp_usage(attack)
    baseline_gy = gy_usage_groups(baseline)
    attack_gy = gy_usage_groups(attack)
    baseline_cca = cca_result_groups(baseline)
    attack_cca = cca_result_groups(attack)
    baseline_charge = charge(baseline)
    attack_charge = charge(attack)
    baseline_packets = packet_count(baseline / "gtpu.pcap")
    attack_packets = packet_count(attack / "gtpu.pcap")

    relations = {
        "identical_gtpu_packet_count":
            baseline_packets == attack_packets and baseline_packets > 0,
        "identical_pfcp_report_count":
            len(baseline_pfcp) == len(attack_pfcp) and len(attack_pfcp) > 0,
        "identical_pfcp_producer_usage": baseline_pfcp == attack_pfcp,
        "baseline_one_usu_per_ccr":
            baseline_gy == [[usage] for usage in baseline_pfcp],
        "attack_two_identical_usu_per_ccr":
            attack_gy == [[usage, usage] for usage in attack_pfcp],
        "attack_gy_exact_x2":
            sum(item[0] for group in attack_gy for item in group)
            == 2 * sum(item[0] for item in attack_pfcp),
        "pfcp_reports_accepted":
            accepted_pfcp_responses(attack) == len(attack_pfcp),
        "baseline_cca_success":
            len(baseline_cca) == len(baseline_pfcp)
            and all(codes == [2001, 2001] for codes in baseline_cca),
        "attack_both_mscc_accepted":
            len(attack_cca) == len(attack_pfcp)
            and all(codes == [2001, 2001, 2001] for codes in attack_cca),
        "backend_charge_increased":
            attack_charge["charged_cents"] > baseline_charge["charged_cents"],
    }
    failed_relations = [name for name, passed in relations.items() if not passed]
    if failed_relations:
        raise PairError(f"failed semantic relations: {failed_relations}")

    original_sum = sum(item[0] for item in attack_pfcp)
    duplicated_sum = sum(item[0] for group in attack_gy for item in group)
    result = {
        "schema_version": "1.0",
        "run_id": f"paired_{baseline.name}__{attack.name}",
        "audit_id": "T4G-A12",
        "legacy_threat_id": "T4-2",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "implementation_profile": "Gy-semantic-analogue",
        "validation": "E2E",
        "classification": "E2E",
        "kernel": attack_environment["kernel"],
        "open5gs_commit": EXPECTED_COMMIT,
        "gtpu_packet_count_each": baseline_packets,
        "report_count": len(attack_pfcp),
        "baseline_mscc_per_ccr": 1,
        "attack_mscc_per_ccr": 2,
        "baseline_pfcp_usage": baseline_pfcp,
        "attack_pfcp_usage": attack_pfcp,
        "attack_gy_usage_groups": attack_gy,
        "original_usage_sum": original_sum,
        "duplicated_gy_usage_sum": duplicated_sum,
        "usage_multiplier": 2,
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents":
            attack_charge["charged_cents"] - baseline_charge["charged_cents"],
        "accepted_pfcp_responses": len(attack_pfcp),
        "accepted_cca_updates": len(attack_cca),
        "accepted_attack_mscc_results": 2 * len(attack_cca),
        "g1_wire_acceptance": True,
        "g2_state_effect": True,
        "g3_backend_effect": True,
        "semantic_relations": relations,
        "input_checksum_counts": {
            "baseline": baseline_checksum_count,
            "attack": attack_checksum_count,
        },
        "claim_boundary": (
            "This paired live run validates intra-CCR MSCC/USU duplication "
            "and accepted Gy CCA-U responses in the Open5GS/SigScale "
            "prototype. Native N40/Nchf CHF acceptance and CCR-I/T capture "
            "are not claimed."
        ),
    }

    output.mkdir(parents=True, exist_ok=False)
    for label, source in (("baseline", baseline), ("attack", attack)):
        target = output / label
        target.mkdir()
        names = [
            "environment.txt",
            "ocs_balance_summary.json",
            "pfcp.pcap",
            "gy.pcap",
            "gtpu.pcap",
            "preflight.json",
            "baseline_trace.txt" if label == "baseline" else "mutation_trace.txt",
        ]
        for name in names:
            shutil.copy2(source / name, target / name)
    (output / "paired_result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    (output / "PAIR_VALIDATION.md").write_text(
        "# T4-2 paired live validation\n\n"
        "Result: `E2E PASS` for the Gy semantic analogue.\n\n"
        f"Both runs contain {baseline_packets:,} GTP-U packets and the same "
        f"{len(attack_pfcp)} PFCP producer reports totaling "
        f"{original_sum:,} bytes. Each attack CCR-U carries two identical "
        "MSCC/USU tuples, producing exactly "
        f"{duplicated_sum:,} Gy-reported bytes (`x2`). Every duplicated MSCC "
        "receives result code 2001. OCS charge increases from "
        f"{baseline_charge['charged_cents']}¢ to "
        f"{attack_charge['charged_cents']}¢.\n\n"
        "The monetary charge is not required to double because tariff-unit "
        "rounding and quota reservation are nonlinear. Exact duplication is "
        "proved at the Gy wire boundary; increased balance consumption proves "
        "the backend effect.\n\n"
        "Claim boundary: this is an Open5GS/SigScale Gy result. Native "
        "N40/Nchf CHF acceptance and CCR-I/T capture are not claimed.\n",
        encoding="utf-8",
    )
    (output / "PROVENANCE.md").write_text(
        "# T4-2 clean-source paired live provenance\n\n"
        f"- Baseline source run: `{baseline.name}`\n"
        f"- Attack source run: `{attack.name}`\n"
        f"- Open5GS commit: `{EXPECTED_COMMIT}`\n"
        "- Kernel: `6.17.0-40-generic`\n"
        "- Workload: 7,600 uplink plus 7,600 downlink ping attempts per run\n"
        "- Baseline source delta: bounded bidirectional 1 MiB fixture only\n"
        "- Attack source delta: the same fixture plus "
        "`t4-2_mscc_duplication.patch`\n\n"
        "The selected package contains raw packet evidence, reduced OCS "
        "balance summaries, preflight records, and source-environment hashes. "
        "Full NF logs and subscriber inventory are excluded because they are "
        "unnecessary for the semantic proof and contain local identifiers.\n",
        encoding="utf-8",
    )
    entries = [
        f"{digest(path)}  {path.relative_to(output)}"
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (output / "SHA256SUMS").write_text(
        "\n".join(entries) + "\n", encoding="utf-8"
    )
    print("T4-2 paired live validation: PASS (Gy semantic analogue)")
    print(f"Gy usage {original_sum:,} -> {duplicated_sum:,} bytes (x2)")
    print(
        f"OCS charge {baseline_charge['charged_cents']} -> "
        f"{attack_charge['charged_cents']} cents"
    )
    print(f"output: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PairError as error:
        print(f"ERROR: {error}")
        raise SystemExit(1) from error
