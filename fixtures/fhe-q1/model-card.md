# FHE-Q1-uint8-v1: public modular circuit

Version: 1. Frozen plaintext fixture; no engine/profile qualification.

## Purpose and license

This is a deliberately small integer circuit for cross-language/encrypted-output
correctness comparisons. It is not a trained classifier and has no predictive
accuracy, real-world generalization or general ML performance claim. All weights,
inputs and expected outputs are public. The synthetic grid and program were
created for Kryvola; all fixture files are Apache-2.0 (full LICENSE included).
There is no downloaded dataset, personal data, training set or learned parameter.

## Reproduction and exact semantics

The input axis is `(0,1,2,7,15,63,127,128,254,255)`. Dataset order is the Cartesian
product with x0 outermost and x1 innermost: exactly 100 cases, split SYNTHETIC.
CSV encoding is ASCII with the published header, comma separator and LF after
every row, including the last. Recreate y0=(3*x0+5*x1+7) mod 256 and
y1=(x0*x1+11) mod 256; no random seed or preprocessing transform is required.

Inputs/outputs are shape [2], unsigned uint8, range 0..255. Fractional bits: 0;
rounding: none; arithmetic: EXACT_MODULAR, wrapping after each ADD/MUL. Signed
values, float coercion, comparisons, argmax and saturation are unsupported.
Public constants are (3,5,7,11). program.txt numbers inputs 0,1, constants 2..5,
then appends six operation results 6..11; outputs are registers 9,11.
Operator counts: three ADD, three MUL. No private weights or secret parameters.

## Error budget and evidence boundaries

Reference correctness requires exact byte reproduction and zero integer
mismatches for all 100 frozen cases. Encrypted evaluation must have zero integer
mismatches on this corpus; this finite test is not a proof over all uint8 inputs.
Predictive accuracy and label-based metrics are not applicable. Cryptographic
parameters, engine image and cryptographic failure/security budgets remain
unbound until M0-PR20 and its reviewed qualification work; no security parameter
is inferred from uint8 arithmetic. No latency, throughput or production claim.

## Frozen byte identities

These are raw-file SHA-256 checksums, not signed or domain-separated spec IDs.
The independently pinned manifest hashes all files, including this card/license.
Later engine release bindings must preserve these exact bytes and explicitly
derive any required spec-domain digest; no placeholder engine descriptor ships.

- program.txt: `247ef123aeea9684b0e1d1f14268b74d9228b4b50ba3aaf007c7fa05235467fb`
- inputs.csv: `355c6ef5c34b25798a4f75bac2fae55ea055ab8971b62865e3995cbc700ffa16`
- expected.csv: `cc714416fc2c6c80d60073ca1fcd2c4d95cdf4989dc38095583b5b327b2c8913`
