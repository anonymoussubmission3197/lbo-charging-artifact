# T4-MOD1 Public Evidence Provenance

This directory contains a sanitized public derivative of a controlled campaign
with three benign baseline runs and three unprotected attack runs.

- Representative: `T4-MOD1`
- Audit identifier: `T4G-A17`
- Implementation profile: Open5GS/SigScale Gy semantic analogue
- Mutation: multiply `CC-Input-Octets` by five
- Preserved values: accepted PFCP usage and `CC-Output-Octets`
- Controlled workload: 30,400 captured GTP-U packets per run
- Repetitions: three baseline and three attack runs
- Observed OCS debit in every pair: 27 to 69 cents

The `baseline/` and `attack/` directories contain one complete representative
pair, including GTP-U, PFCP, and Gy captures. The `repetitions/` directory
contains sanitized PFCP and Gy captures for all six runs. Timestamps, network
addresses, subscriber identifiers, Diameter identities, and Session-Ids were
deterministically pseudonymized while preserving packet lengths and semantics.

The prototype generated five accepted CCR-U/CCA-U exchanges per run. Clean
PFCP session deletion is captured and accepted. The prototype did not generate
CCR-T, so CCR-T acceptance is not claimed. Native N40/Nchf CHF acceptance is
also outside this Gy analogue's claim boundary.
