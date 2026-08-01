# Public Analysis Data Dictionary

This directory exposes the paper's standard-driven analysis at row level. All
released columns and values are English-only. The tables retain 3GPP document,
version, and clause references so that a reviewer can trace an entry back to
its normative source.

## Counting boundary

The native paper scope comprises N7 (`T1`), N4 (`T2` and `T3`), and N40
(`T4-Nchf`). The laboratory's separate `T4-Gy` measurement analogue is not part
of the native standard-analysis counts and is excluded from these tables.

The complete source audit contains 2,370 field positions, 97 constraints, and
276 scenarios when that analogue is included. Applying the native-surface
boundary yields 2,280 field positions, 81 consistency constraints, and 232
threat scenarios. Of the 2,280 native positions, 230 are classified as
`NON_CHARGING`; removing them yields 2,050 charging-relevant positions.

| Surface | All field positions | Charging-relevant | Constraints | Scenarios |
|---|---:|---:|---:|---:|
| T1 / N7 | 249 | 201 | 13 | 41 |
| T2 / N4, V-SMF to V-UPF | 908 | 802 | 24 | 65 |
| T3 / N4, V-UPF to V-SMF | 271 | 201 | 20 | 51 |
| T4 / N40 | 852 | 846 | 24 | 75 |
| **Total** | **2,280** | **2,050** | **81** | **232** |

## Released tables

### `all_field_positions_2280.csv`

One row per audited native field position. `field_position_id` is a stable
release-local identifier. The standard source is captured by
`standard_document`, `standard_version`, and `standard_reference`.
`charging_relevance` records the audit classification. `constraint_ids` and
`scenario_ids` are pipe-separated references to the other released tables.

### `charging_relevant_fields_2050.csv`

An exact subset of `all_field_positions_2280.csv` after removing rows whose
`charging_relevance` is `NON_CHARGING`. Identifiers are preserved, so a row can
be joined directly to the full inventory.

### `consistency_constraints_81.csv`

One row per native cross-field or cross-message consistency constraint.
`left_paths` and `right_paths` identify the related positions;
`relation_type` classifies the relation; and `scenario_ids` links the
constraint to candidate threats.

### `threat_scenarios_232.csv`

One row per retained native threat scenario. Each row reports the English
scenario name, matching field pattern and examples, related constraint IDs,
attacker position, violated invariants, validation priority, standard basis,
and expected evidence. These are the 232 systematically derived scenarios,
not 232 implemented attacks.

### `derivation_crosswalk.csv`

A compact join table for the 2,050 charging-relevant positions. It connects
each field position to the constraint and scenario identifiers recorded by the
audit. Empty references mean that the field was retained as charging-relevant
without a direct row-level link in the released audit.

### `coverage_summary.json`

Machine-readable aggregate and per-surface counts used by the reviewer CLI.
The JSON also records the canonical filenames in this directory.

## Five manipulation methods and representative PoCs

The 232 scenarios are grouped by the five manipulation methods used in the
paper: modification (`MOD`), insertion (`INS`), deletion (`DEL`), duplication
(`DUP`), and sequence manipulation (`SEQ`). Their per-cell counts and the 19
implemented representatives are published in `../manifest/cells.yaml`.
`T1-INS` contains zero retained scenarios and is intentionally N/A.

The source audit does not encode a unique scenario-to-cell label for every
scenario. This release therefore does not invent one. The published
crosswalks expose only relationships that are explicitly present in the
audited source data.

## Release transformations

`../scripts/build_analysis_release.py` implements the deterministic selection,
renaming, reference checking, row-count checking, and English-only validation
used to create these files. Internal notes, non-English annotations, source
filesystem paths, and verbatim specification snippets are not released. This
keeps the dataset anonymous and focused while preserving identifiers and
standard citations needed to inspect the analysis.
