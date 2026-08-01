#!/usr/bin/env python3
"""Build the English-only, paper-aligned analysis tables for public release."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import re
import sys


FIELD_SOURCE = "01_STANDARD_FIELD_RELEVANCE_COVERAGE.csv"
CONSTRAINT_SOURCE = "02_STANDARD_RELATION_COVERAGE.csv"
SCENARIO_SOURCE = "03_CHARGING_THREAT_SCENARIOS.csv"

FIELD_OUTPUT = "all_field_positions_2280.csv"
RELEVANT_OUTPUT = "charging_relevant_fields_2050.csv"
CONSTRAINT_OUTPUT = "consistency_constraints_81.csv"
SCENARIO_OUTPUT = "threat_scenarios_232.csv"
CROSSWALK_OUTPUT = "derivation_crosswalk.csv"

NATIVE_SURFACES = {"T1", "T2", "T3", "T4-Nchf"}
HANGUL = re.compile(r"[\uac00-\ud7a3]")


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write_rows(
    path: Path, fieldnames: list[str], rows: list[dict[str, str]]
) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def normalize_attacker(value: str) -> str:
    intermediate_host = " \ub610\ub294 \uc911\uac04 host"
    serializer_host = " \ub610\ub294 serializer host"
    return (
        value.replace(intermediate_host, " or intermediate host")
        .replace(serializer_host, " or serializer host")
    )


def split_ids(value: str) -> set[str]:
    return {item.strip() for item in value.split("|") if item.strip()}


def assert_english(rows: list[dict[str, str]], label: str) -> None:
    for row_number, row in enumerate(rows, start=2):
        for column, value in row.items():
            if HANGUL.search(value or ""):
                raise ValueError(
                    f"{label}:{row_number}:{column} contains Hangul text"
                )


def build(source_dir: Path, output_dir: Path) -> None:
    source_fields = read_rows(source_dir / FIELD_SOURCE)
    source_constraints = read_rows(source_dir / CONSTRAINT_SOURCE)
    source_scenarios = read_rows(source_dir / SCENARIO_SOURCE)

    native_fields = [r for r in source_fields if r["surface"] in NATIVE_SURFACES]
    native_constraints = [
        r for r in source_constraints if r["surface"] in NATIVE_SURFACES
    ]
    native_scenarios = [
        r for r in source_scenarios if r["surface"] in NATIVE_SURFACES
    ]
    relevant_fields = [
        r for r in native_fields if r["charging_relevance"] != "NON_CHARGING"
    ]

    expected = {
        "native fields": (len(native_fields), 2280),
        "charging-relevant fields": (len(relevant_fields), 2050),
        "consistency constraints": (len(native_constraints), 81),
        "threat scenarios": (len(native_scenarios), 232),
    }
    for label, (actual, wanted) in expected.items():
        if actual != wanted:
            raise ValueError(f"{label}: expected {wanted}, found {actual}")

    field_columns = [
        "field_position_id", "surface", "message", "message_variant", "protocol",
        "field_path", "parent_path", "field_name", "field_kind", "presence",
        "cardinality", "data_type", "standard_document", "standard_version",
        "standard_reference", "charging_relevance", "relevance_reason",
        "constraint_ids", "scenario_ids", "review_status",
    ]
    field_rows: list[dict[str, str]] = []
    for index, source in enumerate(native_fields, start=1):
        field_rows.append({
            "field_position_id": f"FP-{index:04d}",
            "surface": source["surface"],
            "message": source["message"],
            "message_variant": source["message_variant"],
            "protocol": source["protocol"],
            "field_path": source["field_path"],
            "parent_path": source["parent_path"],
            "field_name": source["field_name"],
            "field_kind": source["field_kind"],
            "presence": source["presence"],
            "cardinality": source["cardinality"],
            "data_type": source["data_type"],
            "standard_document": source["standard_document"],
            "standard_version": source["standard_version"],
            "standard_reference": source["source_clause_or_table"],
            "charging_relevance": source["charging_relevance"],
            "relevance_reason": source["relevance_reason"],
            "constraint_ids": source["relation_ids"],
            "scenario_ids": source["candidate_scenario_ids"],
            "review_status": source["review_status"],
        })
    relevant_rows = [
        row for row in field_rows if row["charging_relevance"] != "NON_CHARGING"
    ]

    constraint_columns = [
        "constraint_id", "surface", "message", "constraint_name", "left_paths",
        "right_paths", "relation_type", "standard_basis", "charging_relevance",
        "scenario_ids",
    ]
    constraint_rows = [{
        "constraint_id": source["relation_id"],
        "surface": source["surface"],
        "message": source["message"],
        "constraint_name": source["relation_name_en"],
        "left_paths": source["left_paths"],
        "right_paths": source["right_paths"],
        "relation_type": source["relation_type"],
        "standard_basis": source["standard_basis"],
        "charging_relevance": source["charging_relevance"],
        "scenario_ids": source["candidate_scenario_ids"],
    } for source in native_constraints]

    scenario_columns = [
        "scenario_id", "surface", "message", "scenario_name", "field_patterns",
        "matched_field_count", "matched_field_examples", "field_mapping_mode",
        "constraint_ids", "attacker_nf", "violated_invariants", "candidate_class",
        "implementation_priority", "testbed_support_expectation",
        "initial_validation_status", "standard_basis", "required_evidence",
        "recommended_workload",
    ]
    scenario_rows = [{
        "scenario_id": source["audit_id"],
        "surface": source["surface"],
        "message": source["message"],
        "scenario_name": source["scenario_name_en"],
        "field_patterns": source["standard_field_patterns"],
        "matched_field_count": source["matched_field_count"],
        "matched_field_examples": source["matched_field_examples"],
        "field_mapping_mode": source["field_mapping_mode"],
        "constraint_ids": source["relation_ids"],
        "attacker_nf": normalize_attacker(source["attacker_nf"]),
        "violated_invariants": source["violated_invariants"],
        "candidate_class": source["candidate_class"],
        "implementation_priority": source["implementation_priority"],
        "testbed_support_expectation": source["testbed_support_expectation"],
        "initial_validation_status": source["initial_validation_status"],
        "standard_basis": source["standard_basis"],
        "required_evidence": source["required_evidence"],
        "recommended_workload": source["recommended_workload"],
    } for source in native_scenarios]

    constraint_ids = {row["constraint_id"] for row in constraint_rows}
    scenario_ids = {row["scenario_id"] for row in scenario_rows}
    for row in field_rows:
        unknown_constraints = split_ids(row["constraint_ids"]) - constraint_ids
        unknown_scenarios = split_ids(row["scenario_ids"]) - scenario_ids
        if unknown_constraints or unknown_scenarios:
            raise ValueError(
                f"unresolved field references for {row['field_position_id']}: "
                f"constraints={sorted(unknown_constraints)}, "
                f"scenarios={sorted(unknown_scenarios)}"
            )
    for row in constraint_rows:
        unknown_scenarios = split_ids(row["scenario_ids"]) - scenario_ids
        if unknown_scenarios:
            raise ValueError(
                f"unresolved constraint references for {row['constraint_id']}: "
                f"{sorted(unknown_scenarios)}"
            )
    for row in scenario_rows:
        unknown_constraints = split_ids(row["constraint_ids"]) - constraint_ids
        if unknown_constraints:
            raise ValueError(
                f"unresolved scenario references for {row['scenario_id']}: "
                f"{sorted(unknown_constraints)}"
            )

    crosswalk_columns = [
        "field_position_id", "surface", "message", "field_path",
        "charging_relevance", "constraint_ids", "scenario_ids",
    ]
    crosswalk_rows = [
        {column: row[column] for column in crosswalk_columns}
        for row in relevant_rows
    ]

    for label, rows in (
        (FIELD_OUTPUT, field_rows),
        (RELEVANT_OUTPUT, relevant_rows),
        (CONSTRAINT_OUTPUT, constraint_rows),
        (SCENARIO_OUTPUT, scenario_rows),
        (CROSSWALK_OUTPUT, crosswalk_rows),
    ):
        assert_english(rows, label)

    output_dir.mkdir(parents=True, exist_ok=True)
    write_rows(output_dir / FIELD_OUTPUT, field_columns, field_rows)
    write_rows(output_dir / RELEVANT_OUTPUT, field_columns, relevant_rows)
    write_rows(output_dir / CONSTRAINT_OUTPUT, constraint_columns, constraint_rows)
    write_rows(output_dir / SCENARIO_OUTPUT, scenario_columns, scenario_rows)
    write_rows(output_dir / CROSSWALK_OUTPUT, crosswalk_columns, crosswalk_rows)

    surface_order = ["T1", "T2", "T3", "T4-Nchf"]
    counts = {
        "messages": 11,
        "native_fields": len(field_rows),
        "native_relevant_fields": len(relevant_rows),
        "native_constraints": len(constraint_rows),
        "manipulation_primitives": 5,
        "native_scenarios": len(scenario_rows),
        "paper_cells": 20,
        "runnable_cell_representatives": 19,
        "n_a_cells": 1,
    }
    per_surface = {
        surface: {
            "field_positions": sum(r["surface"] == surface for r in field_rows),
            "charging_relevant_fields": sum(
                r["surface"] == surface for r in relevant_rows
            ),
            "consistency_constraints": sum(
                r["surface"] == surface for r in constraint_rows
            ),
            "threat_scenarios": sum(
                r["surface"] == surface for r in scenario_rows
            ),
        }
        for surface in surface_order
    }
    summary = {
        "schema_version": "4.0",
        "counts": counts,
        "per_surface": per_surface,
        "files": {
            "all_field_positions": FIELD_OUTPUT,
            "charging_relevant_fields": RELEVANT_OUTPUT,
            "consistency_constraints": CONSTRAINT_OUTPUT,
            "threat_scenarios": SCENARIO_OUTPUT,
            "derivation_crosswalk": CROSSWALK_OUTPUT,
        },
        "note": (
            "Paper-aligned native N7, N4, and N40 counts. The separate T4-Gy "
            "measurement analogue is excluded. T1-INS is N/A with zero retained "
            "scenarios."
        ),
    }
    (output_dir / "coverage_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "analysis",
    )
    args = parser.parse_args()
    try:
        build(args.source_dir.resolve(), args.output_dir.resolve())
    except (OSError, ValueError, KeyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Built paper-aligned public analysis tables:")
    for name in (
        FIELD_OUTPUT, RELEVANT_OUTPUT, CONSTRAINT_OUTPUT, SCENARIO_OUTPUT,
        CROSSWALK_OUTPUT, "coverage_summary.json",
    ):
        print(f"  {args.output_dir / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
