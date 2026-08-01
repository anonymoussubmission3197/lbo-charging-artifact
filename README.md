# LBO Charging Attack Artifact

This anonymous artifact accompanies an INFOCOM submission. It exposes the
paper's `4 charging surfaces × 5 manipulation methods` as twenty cells:

```text
               MOD       INS       DEL       DUP       SEQ
T1 / N7        E2E       N/A       E2E       E2E       E2E
T2 / N4        E2E       E2E       E2E       E2E       E2E
T3 / N4        E2E       E2E       E2E       E2E       E2E
T4 / charging  E2E       E2E       E2E       E2E       E2E
```

There are nineteen runnable representatives. `T1-INS` is intentionally N/A
because the standard analysis retained zero scenarios in that cell; it is not
a missing implementation.

The analysis reported by the paper is:

```text
11 selected messages
→ 2,280 field positions
→ 2,050 charging-relevant field positions
→ 81 consistency constraints
→ 5 manipulation methods (MOD, INS, DEL, DUP, SEQ)
→ 232 threat scenarios
→ 19 representative PoCs
```

## Reviewer quick start

The verifier requires Python 3.10 or later, PyYAML, and TShark 3.6 or later.
It has been tested with Ubuntu 22.04 / Python 3.10 / TShark 3.6.2 and Ubuntu
24.04 / Python 3.12 / TShark 4.2.2.

```bash
sudo apt update
sudo apt install -y git python3 python3-yaml tshark

git clone https://github.com/anonymoussubmission3197/lbo-charging-artifact.git
cd lbo-charging-artifact
./bin/lbo-artifact doctor
./bin/lbo-artifact verify --all

COLUMNS=140 ./bin/lbo-artifact demo
```

Expected verification result:

```text
Summary: 19/19 runnable PASS; T1-INS N/A (0 scenarios)
```

The full-screen demo accepts a mouse click or Up/Down plus Enter. After a PoC
finishes, Enter returns to the twenty-cell menu. `T1-INS` is visible but cannot
be opened. Each runnable PoC presents the standard-derived position, the
whole-system attack location, the measured benign-versus-attack outcome, and
the corresponding paper defense predicate. The final screen also prints two
copyable Wireshark commands for the selected PFCP and Gy captures.

To inspect one verifier in detail:

```bash
./bin/lbo-artifact verify T3-DEL1
```

All verification is offline and read-only. These commands do not start 5G
network functions, modify a charging backend, or transmit traffic.

## Packet captures

`pcaps/` provides a compact capture set named by representative and interface,
for example `T3-DEL1_pfcp.pcap` and `T3-DEL1_gy.pcap`. Every runnable PoC has
PFCP and Gy captures; `T1-MOD1` additionally has a reduced N7 capture.
`pcaps/index.json` records each selected capture and its digest.

Example inspection:

```bash
tshark -r pcaps/T3-DEL1_pfcp.pcap -q -z io,phs
tshark -r pcaps/T3-DEL1_gy.pcap -q -z io,phs
```

The captures are laboratory-generated research data. Public copies were
pseudonymized or reduced to remove identifying network and subscriber values.
The larger `evidence/` packages are the checksum-protected inputs used by the
offline verifier.

## What is included

- `bin/lbo-artifact`: reviewer entry point;
- `manifest/`: the twenty cells, eleven-message scope, and nineteen evidence
  mappings;
- `analysis/coverage_summary.json`: paper-aligned aggregate counts;
- `evidence/`: measured benign/attack evidence for the nineteen PoCs;
- `attacks/`: Open5GS mutation patches, organized by current representative ID;
- `pcaps/`: compact pseudonymized capture collection; and
- `scripts/` and `tests/`: offline verification code and regression tests.

## Claim boundaries

The T4 executions use an Open5GS/SigScale Gy prototype as a semantic analogue;
they do not claim native N40/CHF acceptance. The paper reports the Charging-TCB
defense evaluation. This public package reproduces the attacks and explains
the relevant defense predicate, but it does not contain the defense
implementation or raw defense-evaluation data.

## Licenses and responsible use

Project-authored software is Apache-2.0. Documentation and research data are
CC BY 4.0. Open5GS-derived mutation patches under `attacks/` are
AGPL-3.0-only. See `LICENSES.md`, `ATTRIBUTION.md`, and `NOTICE`.

Use the attack patches only in an isolated, authorized laboratory. Do not use
them against production networks or systems without explicit permission.
