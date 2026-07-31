#!/usr/bin/env python3
"""Finalize the bidirectional T3-4 ULVOL-suppression live pair."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from t3_mod1 import packet_count, pfcp_usage
from t3_dup1 import (
    PairError,
    accepted,
    charge,
    environment,
    fields,
    gy,
    verify_run,
)


EXPECTED_COMMIT = "26cbc33a418a292e3b3949be69155898d751bd6e"


def boolean_field(value: str) -> bool:
    """Normalize Boolean field output across supported TShark releases."""
    normalized = value.strip().lower()
    if normalized in {"true", "1", "set", "yes"}:
        return True
    if normalized in {"false", "0", "not set", "no", ""}:
        return False
    raise PairError(f"unsupported Boolean field value: {value!r}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def suppressed_pfcp(run_dir: Path) -> list[dict]:
    rows = fields(
        run_dir / "pfcp.pcap",
        "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
        (
            "pfcp.volume_measurement_flags.tovol",
            "pfcp.volume_measurement_flags.ulvol",
            "pfcp.volume_measurement_flags.dlvol",
            "pfcp.ie_type",
            "pfcp.ie_len",
            "pfcp.volume_measurement.tovol",
            "pfcp.volume_measurement.ulvol",
            "pfcp.volume_measurement.dlvol",
        ),
    )
    reports = []
    for row in rows:
        row += [""] * (8 - len(row))
        types = [int(value) for value in row[3].split(",") if value]
        lengths = [int(value) for value in row[4].split(",") if value]
        volume_lengths = [
            length for ie_type, length in zip(types, lengths) if ie_type == 66
        ]
        total, downlink = int(row[5]), int(row[7])
        reports.append({
            "tovol": boolean_field(row[0]),
            "ulvol": boolean_field(row[1]),
            "dlvol": boolean_field(row[2]),
            "ie_length": volume_lengths[0] if len(volume_lengths) == 1 else None,
            "total": total,
            "uplink_present": row[6] != "",
            "downlink": downlink,
            "inferred_omitted_uplink": total - downlink,
        })
    return reports


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
    if attack_env.get("case_id") != "T3-4":
        raise PairError("attack case mismatch")

    baseline_pfcp = pfcp_usage(baseline)
    attack_reports = suppressed_pfcp(attack)
    if len(baseline_pfcp) != len(attack_reports) or not attack_reports:
        raise PairError("report count mismatch")
    if any(
        not report["tovol"]
        or report["ulvol"]
        or not report["dlvol"]
        or report["uplink_present"]
        or report["ie_length"] != 41
        or report["inferred_omitted_uplink"] <= 0
        for report in attack_reports
    ):
        raise PairError("TOVOL/ULVOL/DLVOL or Type 66 length relation failed")
    attack_inferred = [
        (report["total"], report["inferred_omitted_uplink"], report["downlink"])
        for report in attack_reports
    ]
    if attack_inferred != baseline_pfcp:
        raise PairError("baseline usage differs from attack inferred actual usage")

    baseline_gy, attack_gy = gy(baseline), gy(attack)
    expected_attack_gy = [
        (report["downlink"], 0, report["downlink"]) for report in attack_reports
    ]
    if baseline_gy != baseline_pfcp or attack_gy != expected_attack_gy:
        raise PairError("directional PFCP to Gy relation failed")
    if accepted(attack, "pfcp") != len(attack_reports):
        raise PairError("not all PFCP responses accepted")
    if accepted(attack, "gy") != len(attack_reports):
        raise PairError("not all CCA-U responses accepted")
    if packet_count(baseline / "gtpu.pcap") != packet_count(attack / "gtpu.pcap"):
        raise PairError("GTP-U workload count differs")
    baseline_charge, attack_charge = charge(baseline), charge(attack)
    if attack_charge["charged_cents"] >= baseline_charge["charged_cents"]:
        raise PairError("suppressed charge did not decrease")

    omitted_ul = sum(report["inferred_omitted_uplink"] for report in attack_reports)
    result = {
        "schema_version": "1.0",
        "legacy_threat_id": "T3-4",
        "audit_id": "T3-A20",
        "experiment_kind": "clean_source_paired_live_reproduction",
        "validation": "E2E",
        "kernel": attack_env["kernel"],
        "open5gs_commit": EXPECTED_COMMIT,
        "report_count": len(attack_reports),
        "gtpu_packet_count_each": packet_count(attack / "gtpu.pcap"),
        "volume_ie_length": 41,
        "flags": {"tovol": True, "ulvol": False, "dlvol": True},
        "baseline_actual_usage": baseline_pfcp,
        "attack_wire_reports": attack_reports,
        "attack_inferred_actual_usage": attack_inferred,
        "baseline_gy_usage": baseline_gy,
        "attack_gy_usage": attack_gy,
        "omitted_uplink_bytes": omitted_ul,
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "accepted_pfcp_responses": len(attack_reports),
        "accepted_cca_updates": len(attack_reports),
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
        "# T3-4 paired live validation\n\n"
        "The baseline and attack carry the same 30,400-packet bidirectional "
        "workload and the same actual total/UL/DL usage. The attack retains "
        "TOVOL and DLVOL, clears ULVOL, and emits a 41-byte Type 66 IE. "
        f"{omitted_ul:,} uplink bytes disappear from Gy, and OCS charge changes "
        f"from {baseline_charge['charged_cents']}¢ to "
        f"{attack_charge['charged_cents']}¢.\n",
        encoding="utf-8",
    )
    (output / "PROVENANCE.md").write_text(
        "# Provenance\n\n"
        f"Baseline source run: `{baseline.name}` (clean bidirectional fixture).\n\n"
        f"Attack source run: `{attack.name}`.\n\n"
        f"Open5GS: `{EXPECTED_COMMIT}`. The attack build adds the common "
        "bidirectional 1 MiB reporting fixture and "
        "`t3-4_ulvol_suppression.patch`.\n",
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
