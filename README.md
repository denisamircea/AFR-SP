# AFR-SP: Agile Forensic-Ready Security and Privacy for Pervasive Systems

Reference code for the paper *Agile Forensic-Ready Security and Privacy for Pervasive Systems (AFR-SP)*
by Mădălina-Elena Tița, Denisa-Florela Mircea and Costin-Anton Boiangiu
(National University of Science and Technology POLITEHNICA Bucharest).

All programs use synthetic data only. They do not access the network, and they read or write only the
files named below. The secure enclave is **emulated in software**; latencies are measured on a laptop,
not on a microcontroller.

## Contents

| File | What it does | Paper section |
|---|---|---|
| `afrsp_poc.py` | Selective cryptographic logger (HMAC chain, signed Merkle checkpoints, circular buffer, verifier) and 15 tamper scenarios | IV.D, Tables II and III |
| `afrsp_gate.py`, `schema.json`, `demo/` | CI/CD gate: Privacy Linter driven by the per-field decision table, plus a forensic admissibility test; three simulated sprints and a 20-snippet linter evaluation | IV.E, Table IV |
| `afrsp_compare.py` | AFR-SP versus verbose logging, a simplified Schneier–Kelsey-style secure log, and masking with a fixed-key chain, on the same trace | IV.F, Table V |
| `results/` | Raw outputs of the runs reported in the paper | |

## Reproduce

Requires Python 3.10 or newer.

```
pip install -r requirements.txt
python3 afrsp_poc.py --seed 7        # about 10-20 s; also try --seed 1, 2, 3
python3 afrsp_gate.py --all          # three sprints + linter evaluation
python3 afrsp_compare.py             # four schemes on the same 86,400 events
```

Single files can be checked with `python3 afrsp_gate.py --target demo/sprint2_bug.py`
(exit code 1 means the gate blocks the change).

## What to expect

Sizes and detection outcomes are deterministic for a given seed; timings vary by a few percent between runs.

* Volume reduction of the selective format versus verbose JSON: 78.69 % (77.98 % including checkpoints).
* None of the values of the fields designated as PII appears in the stored output. This is not a proof of
  anonymity: timestamps, sequence numbers and the device identity remain.
* `afrsp_poc.py`: 14 of 15 scenarios detected; the exception (a collector that deletes the newest checkpoint)
  is detected once the node uploads its next checkpoint, as reported in the paper.
* `afrsp_gate.py`: sprint 1 passes, sprint 2 is blocked, sprint 3 passes; the linter detects 10 of 10 direct
  violations, flags 0 of 8 clean snippets and misses the 2 indirect cases.
* `afrsp_compare.py`: AFR-SP detects 9 of 9 tamper scenarios against 6 (SK) and 5 (Mask).

## Measurement environment of the reported runs

MacBook Pro, Apple M2 Max, 32 GB RAM, macOS 26.1, Python 3.13.18, OpenSSL 3.5.9, cryptography 50.0.2.
The `results/` folder holds the outputs of four runs of `afrsp_poc.py` (seeds 7, 1, 2, 3), of the gate and of
the comparison. Timings in a repeated run can differ slightly from the figures printed in the paper.

## Limitations

* Software-emulated enclave and synthetic events; no on-device (ESP32-S3) measurement yet.
* The Schneier–Kelsey-style baseline is a simplified re-implementation (key evolution and chaining only).
* The Privacy Linter is a static check over Python logging calls and misses personal data that is passed
  through helper functions or intermediate variables.
* The GitHub Actions workflow in `.github/workflows/` has not been run on a hosted runner at the time of writing.

## License

MIT, see `LICENSE`.
