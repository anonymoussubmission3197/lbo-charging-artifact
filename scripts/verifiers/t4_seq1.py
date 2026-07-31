#!/usr/bin/env python3
"""Finalize a clean-source T4-3 semantic CCR replay pair."""

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
from t4_dup1 import cca_result_groups, gy_usage_groups


EXPECTED_COMMIT = "26cbc33a418a292e3b3949be69155898d751bd6e"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def ccr_updates(directory: Path) -> list[dict]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1 "
        "&& diameter.CC-Request-Type == 2",
        (
            "diameter.Session-Id",
            "diameter.CC-Request-Number",
            "diameter.hopbyhopid",
            "diameter.endtoendid",
            "diameter.CC-Input-Octets",
            "diameter.CC-Output-Octets",
        ),
    )
    updates = []
    for row in rows:
        row += ("",) * (6 - len(row))
        if any("," in value for value in row[1:]):
            raise PairError("unexpected repeated field inside T4-3 CCR-U")
        uplink, downlink = int(row[4]), int(row[5])
        updates.append({
            "session_id": row[0],
            "request_number": int(row[1]),
            "hop_by_hop_id": row[2],
            "end_to_end_id": row[3],
            "usage": (uplink + downlink, uplink, downlink),
        })
    if not updates:
        raise PairError(f"no Gy CCR-U requests in {directory}")
    return updates


def aggregate(values: list[tuple[int, int, int]]) -> tuple[int, int, int]:
    return tuple(sum(value[index] for value in values) for index in range(3))


def replay_pairs(updates: list[dict]) -> list[tuple[dict, dict]]:
    grouped: dict[int, list[dict]] = {}
    for update in updates:
        grouped.setdefault(update["request_number"], []).append(update)
    if sorted(grouped) != list(range(1, len(grouped) + 1)):
        raise PairError("CCR-U request numbers are not contiguous")
    if any(len(group) != 2 for group in grouped.values()):
        raise PairError("each request number must occur exactly twice")
    return [(grouped[number][0], grouped[number][1]) for number in sorted(grouped)]


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
        or attack_environment.get("case_id") != "T4-3"
        or attack_preflight.get("case_id") != "T4-3"
    ):
        raise PairError("baseline/attack case identity mismatch")

    baseline_pfcp = pfcp_usage(baseline)
    attack_pfcp = pfcp_usage(attack)
    baseline_gy = gy_usage_groups(baseline)
    attack_gy = gy_usage_groups(attack)
    baseline_updates = ccr_updates(baseline)
    attack_updates = ccr_updates(attack)
    pairs = replay_pairs(attack_updates)
    baseline_cca = cca_result_groups(baseline)
    attack_cca = cca_result_groups(attack)
    baseline_charge = charge(baseline)
    attack_charge = charge(attack)
    baseline_packets = packet_count(baseline / "gtpu.pcap")
    attack_packets = packet_count(attack / "gtpu.pcap")

    baseline_gy_usage = [group[0] for group in baseline_gy]
    attack_pair_usage = [pair[0]["usage"] for pair in pairs]
    pair_relations = [
        {
            "request_number": original["request_number"],
            "same_session": original["session_id"] == replay["session_id"],
            "same_request_number":
                original["request_number"] == replay["request_number"],
            "same_usage": original["usage"] == replay["usage"],
            "fresh_hop_by_hop":
                original["hop_by_hop_id"] != replay["hop_by_hop_id"],
            "fresh_end_to_end":
                original["end_to_end_id"] != replay["end_to_end_id"],
        }
        for original, replay in pairs
    ]
    relations = {
        "identical_gtpu_packet_count":
            baseline_packets == attack_packets and baseline_packets > 0,
        "identical_pfcp_report_count":
            len(baseline_pfcp) == len(attack_pfcp) and len(attack_pfcp) > 0,
        "identical_pfcp_aggregate":
            aggregate(baseline_pfcp) == aggregate(attack_pfcp),
        "baseline_pfcp_equals_gy": baseline_gy_usage == baseline_pfcp,
        "attack_pfcp_equals_original_ccr": attack_pair_usage == attack_pfcp,
        "five_semantic_replay_pairs":
            len(pairs) == 5
            and all(all(value for key, value in item.items()
                        if key != "request_number") for item in pair_relations),
        "attack_ten_single_usu_ccr":
            len(attack_gy) == 10 and all(len(group) == 1 for group in attack_gy),
        "attack_gy_exact_x2":
            sum(group[0][0] for group in attack_gy)
            == 2 * sum(item[0] for item in attack_pfcp),
        "pfcp_reports_accepted":
            accepted_pfcp_responses(attack) == len(attack_pfcp),
        "baseline_cca_success":
            len(baseline_cca) == 5
            and all(codes == [2001, 2001] for codes in baseline_cca),
        "attack_ten_cca_success":
            len(attack_cca) == 10
            and all(codes == [2001, 2001] for codes in attack_cca),
        "backend_charge_increased":
            attack_charge["charged_cents"] > baseline_charge["charged_cents"],
    }
    failed = [name for name, passed in relations.items() if not passed]
    if failed:
        raise PairError(f"failed semantic relations: {failed}")

    original_sum = sum(item[0] for item in attack_pfcp)
    replayed_sum = sum(group[0][0] for group in attack_gy)
    result = {
        "schema_version": "1.0",
        "run_id": f"paired_{baseline.name}__{attack.name}",
        "audit_id": "T4G-A03",
        "legacy_threat_id": "T4-3",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "implementation_profile": "Gy-semantic-analogue",
        "validation": "E2E",
        "classification": "E2E",
        "kernel": attack_environment["kernel"],
        "open5gs_commit": EXPECTED_COMMIT,
        "gtpu_packet_count_each": baseline_packets,
        "pfcp_report_count": len(attack_pfcp),
        "semantic_replay_pair_count": len(pairs),
        "attack_ccr_update_count": len(attack_updates),
        "pair_relations": pair_relations,
        "original_usage_sum": original_sum,
        "replayed_gy_usage_sum": replayed_sum,
        "usage_multiplier": 2,
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents":
            attack_charge["charged_cents"] - baseline_charge["charged_cents"],
        "accepted_pfcp_responses": len(attack_pfcp),
        "accepted_cca_updates": len(attack_cca),
        "g1_wire_acceptance": True,
        "g2_state_effect": True,
        "g3_backend_effect": True,
        "semantic_relations": relations,
        "input_checksum_counts": {
            "baseline": baseline_checksum_count,
            "attack": attack_checksum_count,
        },
        "claim_boundary": (
            "This paired live run validates semantic CCR-U replay with fresh "
            "Diameter transport identifiers and accepted Gy CCA-U responses. "
            "Native N40/Nchf CHF acceptance and CCR-I/T capture are not claimed."
        ),
    }

    output.mkdir(parents=True, exist_ok=False)
    for label, source in (("baseline", baseline), ("attack", attack)):
        target = output / label
        target.mkdir()
        names = [
            "environment.txt", "ocs_balance_summary.json", "pfcp.pcap",
            "gy.pcap", "gtpu.pcap", "preflight.json",
            "baseline_trace.txt" if label == "baseline" else "mutation_trace.txt",
        ]
        for name in names:
            shutil.copy2(source / name, target / name)
    (output / "paired_result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    (output / "PAIR_VALIDATION.md").write_text(
        "# T4-3 paired live validation\n\n"
        "Result: `E2E PASS` for the Gy semantic analogue.\n\n"
        f"Both runs contain {baseline_packets:,} GTP-U packets and five PFCP "
        f"producer reports totaling {original_sum:,} bytes. The attack emits "
        "five semantic replay pairs: Session-Id, CC-Request-Number, and usage "
        "are equal within each pair, while Hop-by-Hop and End-to-End IDs are "
        f"fresh. All 10 CCA-U messages return 2001, submitted usage is "
        f"{replayed_sum:,} bytes, and OCS charge increases from "
        f"{baseline_charge['charged_cents']}¢ to "
        f"{attack_charge['charged_cents']}¢.\n\n"
        "Claim boundary: this is an Open5GS/SigScale Gy result. Native "
        "N40/Nchf CHF acceptance and CCR-I/T capture are not claimed.\n",
        encoding="utf-8",
    )
    (output / "PROVENANCE.md").write_text(
        "# T4-3 clean-source paired live provenance\n\n"
        f"- Baseline source run: `{baseline.name}`\n"
        f"- Attack source run: `{attack.name}`\n"
        f"- Open5GS commit: `{EXPECTED_COMMIT}`\n"
        "- Kernel: `6.17.0-40-generic`\n"
        "- Baseline delta: bounded bidirectional 1 MiB fixture only\n"
        "- Attack delta: the same fixture plus "
        "`t4-3_semantic_ccr_replay.patch`\n\n"
        "Full NF logs and subscriber inventory are excluded from the selected "
        "package because they are unnecessary for the semantic proof and "
        "contain local identifiers.\n",
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
    print("T4-3 paired live validation: PASS (Gy semantic analogue)")
    print(f"Gy usage {original_sum:,} -> {replayed_sum:,} bytes (x2)")
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
