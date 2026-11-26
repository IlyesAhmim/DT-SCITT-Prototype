# dt-evidence-1: research prototype, test vectors, and experiments

Supplementary material for *Verifiable Evidence of Digital Twin Behavior Across
Organizations: A SCITT Profile for the ETSI TS 103 846 Architecture*
(IEEE Communications Standards Magazine submission).

dt-evidence-1 is a profile of the SCITT architecture (RFC 9943) for records of
digital twin (DT) behavior. Each selected event has two parts:

* an **event body**, a JSON object canonicalized with JCS (RFC 8785), kept in the
  operator's evidence store;
* a **SCITT Signed Statement** (COSE_Sign1, Ed25519 with the fully specified COSE
  algorithm -19 of RFC 9864) whose payload is the SHA-256 digest of the body and
  whose protected header carries the issuer and the DT identifier (CWT claims
  `iss` and `sub`), the profile identifier, the per-DT sequence number and the
  predecessor commitment.

A Transparency Service accepts, for each DT, only the successor of the registered
head, publishes signed checkpoints for an RFC 9162-based Merkle log that also commit
to a per-DT head map, and returns COSE inclusion receipts. Four witnesses
recompute the log root and the head map and reapply the per-DT succession rules
before cosigning (a quorum of at least three). The commitment is SHA-256 of
the original signed statement bytes, before receipt attachment. The prototype
stores statements and receipts separately.

## Layout

| Path | Content |
|---|---|
| `dt_evidence/jcs.py` | RFC 8785 canonicalization for the value types of the profile |
| `dt_evidence/merkle.py` | RFC 9162 tree, inclusion and consistency proofs, compact range |
| `dt_evidence/cose.py` | COSE_Sign1 with Ed25519, COSE Receipts for RFC9162_SHA256 |
| `dt_evidence/profile.py` | Event body rules, Signed Statement construction, commitment |
| `dt_evidence/trust.py` | Key status history; emulated time-stamping authority |
| `dt_evidence/registry.py` | Transparency Service (profile or generic registration policy) and witnesses |
| `dt_evidence/verifier.py` | Verifier with three levels: B0 signed chain, B1 tested SCITT baseline, B2 dt-evidence-1 |
| `dt_evidence/producer.py` | Evidence producer for one DT (chain state, DTD and policy bindings) |
| `experiments/detect.py` | Manipulation campaign (Table III of the article) |
| `experiments/bench.py` | Processing costs and sizes |
| `experiments/tradeoff.py` | Time to reliance versus exposure under emulated network delay (Fig. 3) |
| `testvectors/` | Generator and deterministic test vectors for the pump 7 example |
| `js-verifier/` | Separate verifier in JavaScript (canonicalize 2.1.0, cbor-x 1.6.0, node:crypto) |
| `tests/` | Unit and end-to-end tests |
| `results/` | Recorded experimental results used in the article |

## Running

Requirements: Python 3.11 or later, Node.js and npm for the JavaScript verifier.
Run the following commands from the repository root. They work in PowerShell
and Unix-like shells when `python` points to Python 3 (use `py -3` on Windows
or `python3` on Unix if needed).

```sh
python -m pip install cryptography cbor2 numpy matplotlib
python -m unittest discover -s tests
python experiments/detect.py 200
python experiments/bench.py
python experiments/tradeoff.py
python testvectors/make_vectors.py
```

The scripts regenerate the supplied results, figures, or test vectors. Keep a
copy of the recorded artifacts if you want to compare runs. Run the benchmark
before the trade-off simulation, which reads `results/bench.json`.

To check the five supplied vectors with the separate JavaScript verifier:

```sh
cd js-verifier
npm ci
npm run verify
cd ..
```

On Windows PowerShell, use `npm.cmd` instead of `npm` if script execution is
restricted. The verifier compares the returned outcome with the expected
outcome and prints the reason for failures; it does not assert expected reasons.
The five vectors cover one valid 18-record history and four invalid variants:
body alteration, suffix withholding, record rewriting, and DTD misbinding.

Experimental pseudorandom inputs and test salts use fixed seeds for reproducibility.
Timings depend on the machine; the supplied benchmark records a two-vCPU
virtual machine (Intel Xeon, Python 3.13.17, cryptography 50.0.1, cbor2 6.1.5).

## What is measured and what is emulated

* Processing costs and sizes are measured on the implementation.
* Network delays are **emulated**: round-trip times are drawn from log-normal
  distributions (sigma 0.3) and combined with the measured costs; no traffic is sent.
  The synchronous delay model overlaps timestamping and registration.
* The time-stamping authority is emulated: its tokens are COSE_Sign1 objects over
  (commitment, generation time). They are not RFC 3161 / EN 319 422 tokens.
  The benchmark measures local emulated timestamping, not a deployed TSA.
* The COSE header labels for the profile identifier, sequence number and
  predecessor are private-use labels (-65537, -65538, -65539); standardization
  could include registering these parameters.
* The manipulation campaign runs constructed attacks against known registry
  state. It shows the reach of each mechanism, not the attack coverage of a deployment.

## Results used in the article

Manipulation campaign (`results/detection.json`): manipulated histories not
accepted as verified, out of 200 per applicable cell. Any result other than
`verified` counts as non-acceptance, including `pending` and `indeterminate`;
this is not necessarily detection of a contradiction. There are 6,200 trials
across 11 scenarios and three configurations, with two scenarios not applicable
to B0. B1 is the tested SCITT baseline, not a limit on all SCITT deployments.

| Manipulation | B0 signed chain | B1 tested SCITT baseline | B2 dt-evidence-1 |
|---|---|---|---|
| Alter a stored record without the signing key | 200/200 | 200/200 | 200/200 |
| Delete a record inside the disclosed history | 200/200 | 200/200 | 200/200 |
| Backdate a record with a key compromised after revocation | 0/200 | 200/200 | 200/200 |
| Operator re-signs an anchored record and re-chains the suffix | 0/200 | 0/200 | 200/200 |
| Withhold the latest records | 0/200 | 0/200 | 200/200 |
| Declare a DTD version other than the recorded one | 0/200 | 0/200 | 200/200 |
| Registry forks its log, one witness colludes | n/a | 200/200 | 200/200 |
| Registry forks its log, two witnesses collude | n/a | 0/200 | 0/200 |
| Replace a released record before it is anchored | 0/200 | 0/200 | 0/200 |
| Never record an event | 0/200 | 0/200 | 0/200 |
| Sign a false reading at recording time | 0/200 | 0/200 | 0/200 |

Processing costs (`results/bench.json`, medians on one core):

* production 0.067 ms, time-stamp 0.035 ms, registration 0.097 ms
* checkpoint with four witnesses: 0.93 ms for 1 record, 26.0 ms for 64
* verification of a 2001-record history: 0.67 s (0.34 ms per record)
* benchmark sizes: body 411 B, statement 238 B, emulated token 128 B,
  receipt 441 B (1,024 entries) to 785 B (2^20 entries), checkpoint 445 B

## Scope and limitations

This research prototype evaluates the core evidence mechanisms. It does not
claim full SCITT or ETSI conformance or production readiness.

* The prototype stores receipts separately and does not implement every SCITT
  receipt requirement (including receipt CWT claims).
* The test salts and keys are deterministic and must not be used in production.
  Deployment requires cryptographically secure, confidential salts and protected keys.
* Per-DT issuer authorization and persistent witness state protected against
  rollback are deployment requirements, not implemented protections in this version.
  The quorum guarantee assumes a common log and witness set, at most one faulty
  witness, and honest witnesses that sign only consistent extensions.
* The verifiers check declared DTD and policy bindings; they do not recompute
  digests of separately disclosed source documents. The `rejection` event code
  is recognized, but a complete rejection-evidence workflow is not evaluated.
* Full interoperability is not established by five vectors. The Python and
  JavaScript implementations differ in their handling of some invalid timestamp
  tokens, which requires additional tests and harmonization.
* The evidence concerns registered histories up to a verified checkpoint.
  It does not establish that all real events were recorded or that source data
  were accurate. The constructed single-DT attack scenarios do not establish
  deployment-wide attack coverage or false-positive rates.

