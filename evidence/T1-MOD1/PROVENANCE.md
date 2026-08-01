# T1-1 Evidence Provenance

The attack and baseline evidence derives from two controlled laboratory runs.
The PFCP and Gy captures use length-preserving deterministic pseudonyms for
subscriber, host, session, and network identifiers, with packet timestamps
shifted to a fixed public epoch. Their packet lengths and protocol semantics
are preserved.

The N7 captures are identity-free, field-reduced derivatives rather than
byte-for-byte copies. They retain only the request and response JSON values
needed to verify 5QI 9 to 9 in the baseline and 5QI 9 to 6 in the attack. Empty
padding frames preserve the documented original request and response frame
numbers; identity-bearing HTTP/2 headers and unrelated traffic are omitted.

`experiment.json` retains only the four cent balances and the two tariff
mappings required for the comparison. Product, subscriber, bucket, host, and
timestamp identifiers are removed.
