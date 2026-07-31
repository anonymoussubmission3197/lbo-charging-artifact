# License Scope

Status: `APPROVED_FOR_RELEASE` on 2026-07-28.

This repository uses three licenses because it contains independently
controlled software, research material, and patches derived from Open5GS.

| Scope | License | Full text |
|---|---|---|
| Project-authored code and tests | Apache License 2.0 | `LICENSE` and `LICENSES/Apache-2.0.txt` |
| Project-authored documentation, diagrams, manifests, analysis data, packet captures, and reduced result records | Creative Commons Attribution 4.0 International | `LICENSES/CC-BY-4.0.txt` |
| Every `attacks/**/*.patch` file derived from Open5GS source | GNU Affero General Public License v3.0 only | `LICENSES/AGPL-3.0-only.txt` |

## Apache-2.0 scope

Unless a more specific rule below applies, project-authored executable and
supporting software in these locations is licensed under Apache-2.0:

- `bin/`
- `scripts/`
- `tests/`
- project-authored configuration and repository-support files

The top-level `LICENSE` is the Apache-2.0 text.

## CC BY 4.0 scope

The following project-authored non-software material is licensed under
CC BY 4.0:

- Markdown documentation;
- `analysis/` and `manifest/` data;
- all material under `evidence/`, including PCAPs and reduced result records;
- documentation under `attacks/`.

Use the attribution statement in `ATTRIBUTION.md`. The released captures are
author-produced laboratory evidence; the maintainer confirmed redistribution
rights and that no external subscriber data was used.

## AGPL-3.0-only scope

All files matching `attacks/**/*.patch` modify or quote Open5GS source and are
distributed under AGPL-3.0-only. They are based on:

- upstream project: Open5GS;
- upstream repository: `https://github.com/open5gs/open5gs`;
- evaluated commit:
  `26cbc33a418a292e3b3949be69155898d751bd6e`;
- upstream license: GNU Affero General Public License v3.

The patch files are not relicensed under Apache-2.0 or CC BY 4.0. Preserve the
provenance in `NOTICE`.

## External dependencies

PyYAML and TShark are runtime dependencies and are not bundled. Open5GS itself
is not bundled. Third-party names and upstream authors are provenance and must
not be removed for double-blind review.
