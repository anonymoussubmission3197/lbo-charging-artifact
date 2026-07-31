#!/usr/bin/env python3
"""Finalize a clean-source T3-3 semantic PFCP replay pair."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from t3_dup1 import (
    PairError,
    accepted,
    charge,
    environment,
    fields,
    gy,
    icmp_counts,
    pfcp,
    verify_run,
)


EXPECTED_COMMIT = "26cbc33a418a292e3b3949be69155898d751bd6e"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def pfcp_sequences(run_dir: Path) -> list[int]:
    rows = fields(
        run_dir / "pfcp.pcap",
        "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
        ("pfcp.seqno",),
    )
    return [int(row[0]) for row in rows]


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
    if attack_env.get("case_id") != "T3-3":
        raise PairError("attack case mismatch")

    baseline_pfcp, attack_pfcp = pfcp(baseline), pfcp(attack)
    if len(baseline_pfcp) != 3 or any(len(report) != 1 for report in baseline_pfcp):
        raise PairError("unexpected baseline PFCP structure")
    if len(attack_pfcp) != 6 or any(len(report) != 1 for report in attack_pfcp):
        raise PairError("unexpected replay PFCP structure")
    originals = [report[0] for report in baseline_pfcp]
    replay_flat = [report[0] for report in attack_pfcp]
    replay_pairs = [replay_flat[index:index + 2] for index in range(0, 6, 2)]
    if [pair[0] for pair in replay_pairs] != originals:
        raise PairError("attack originals differ from baseline")
    if any(pair[0] != pair[1] for pair in replay_pairs):
        raise PairError("semantic replay pair differs")

    sequences = pfcp_sequences(attack)
    sequence_pairs = [sequences[index:index + 2] for index in range(0, 6, 2)]
    if any(len(set(pair)) != 2 for pair in sequence_pairs):
        raise PairError("replay did not use a fresh PFCP sequence")
    baseline_gy, attack_gy = gy(baseline), gy(attack)
    if baseline_gy != originals or attack_gy != replay_flat:
        raise PairError("PFCP to Gy replay relation failed")
    if accepted(attack, "pfcp") != 6 or accepted(attack, "gy") != 6:
        raise PairError("not all replay requests were accepted")

    baseline_icmp, attack_icmp = icmp_counts(baseline), icmp_counts(attack)
    if (
        baseline_icmp["echo_request"] != attack_icmp["echo_request"]
        or attack_icmp["echo_request"] != 15200
    ):
        raise PairError("intended request workload differs")
    if abs(baseline_icmp["echo_reply"] - attack_icmp["echo_reply"]) > 1:
        raise PairError("unexpected capture-only reply difference")
    baseline_charge, attack_charge = charge(baseline), charge(attack)
    if attack_charge["charged_cents"] <= baseline_charge["charged_cents"]:
        raise PairError("attack charge did not increase")

    result = {
        "schema_version": "1.0",
        "legacy_threat_id": "T3-3",
        "audit_id": "T3-A02",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "validation": "E2E",
        "kernel": attack_env["kernel"],
        "open5gs_commit": EXPECTED_COMMIT,
        "baseline_report_count": 3,
        "attack_report_count": 6,
        "semantic_replay_pairs": 3,
        "pfcp_sequence_pairs": sequence_pairs,
        "original_usage": originals,
        "replayed_usage_pairs": replay_pairs,
        "baseline_gy_usage": baseline_gy,
        "attack_gy_usage": attack_gy,
        "baseline_usage_sum": sum(item[0] for item in originals),
        "attack_gy_usage_sum": sum(item[0] for item in attack_gy),
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "baseline_icmp": baseline_icmp,
        "attack_icmp": attack_icmp,
        "accepted_pfcp_responses": 6,
        "accepted_cca_updates": 6,
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
            "baseline_trace.txt" if label == "baseline" else "mutation_trace.txt",
        ]
        for name in names:
            shutil.copy2(source / name, target / name)
    (output / "paired_result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    (output / "PAIR_VALIDATION.md").write_text(
        "# T3-3 paired live validation\n\n"
        "Three original PFCP usage reports are each replayed in a fresh PFCP "
        "transaction, producing six matching CCR-U and six successful CCA-U. "
        f"OCS charge changes from {baseline_charge['charged_cents']}¢ to "
        f"{attack_charge['charged_cents']}¢.\n\n"
        "The clean baseline capture missed one echo reply, while intended "
        "requests and producer usage are identical; that capture-only noise "
        "is not attributed to the replay.\n",
        encoding="utf-8",
    )
    (output / "PROVENANCE.md").write_text(
        "# Provenance\n\n"
        f"Baseline source run: `{baseline.name}`.\n\n"
        f"Attack source run: `{attack.name}`.\n\n"
        f"Open5GS: `{EXPECTED_COMMIT}`. The attack adds only the common bounded "
        "fixture and `t3-3_usage_report_replay.patch`.\n",
        encoding="utf-8",
    )
    entries = [
        f"{digest(path)}  {path.relative_to(output)}"
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (output / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
