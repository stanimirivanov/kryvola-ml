# Fixed FHE-Q1 plan compiler

`kryvola_ml.planner.compile_fixed_plan` compiles the public program in
`fixtures/fhe-q1/program.txt` and a Spec model descriptor. The owner supplies
`ApprovedBindings` with the tenant and independently verified digests for the
key context, model, engine, paired input manifest and consent. The descriptor
must match the approved model and engine and the frozen program and parameter
digests. Pass `assurance="CONFIDENTIALITY_ONLY"`.

The compiler accepts two uint8 inputs and two uint8 outputs, with public
constants and exact ADD/MUL arithmetic modulo 256. The fixed program computes
`(3*x0 + 5*x1 + 7, x0*x1 + 11)`. A changed program, hidden model, precision
or shape change, nonzero numerical error budget, or stronger assurance
request raises `PlanError("PLAN_REJECTED")`.

The result contains unsigned canonical Spec v2 plan bytes, their BLAKE3
plan commitment, and four immutable metadata byte strings:

- `output_contract` describes exact arithmetic, framing, and owner plaintext visibility.
- `resource_profile` records operation counts and conservative native byte bounds
  for input and output pairs and the evaluation key.
- `evidence_policy` requires consent for unverified release and independent
  exact-release authorization. Computation integrity is unproven.
- `leakage_profile` records public model visibility and the FHE-Q1 leakage classes.

The plan binds each metadata byte string using the Spec full-blob commitment.
These four metadata formats are local versioned planner artifacts. The owner
agent validates consent and authorization and signs the canonical plan outside
the compiler. The canonical bytes use the ASCII subset of the Spec encoding.
The tests check a digest reproduced with the Spec reference implementation.

The ML artifact pin adopts the merged Spec PR3 revision, which includes the
PR2 runtime contracts. BLAKE3 is provided by the pinned Python `blake3` package.
