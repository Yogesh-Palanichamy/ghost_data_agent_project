# Ghost Data Still Exists — Deletion Audit Agent

## Overview

This solution uses a deterministic Python audit pipeline rather than an external LLM. It reads the participant-facing CSVs and local evidence corpus, resolves current and historical identifiers, parses JSON/SQL/log/text/PDF/image evidence, applies the supplied policy categories, and writes the root-level `output.csv`.

The agent treats workflow status and activity results as claims. Activity timestamps can help locate resources, but record states are based on evidence snapshots and point lookups. The audit cutoff is applied before evidence is considered. Findings, remediation, and verification steps use the allowed operation vocabulary and deterministic ordering.

## Requirements

- Python 3.10+
- Standard-library modules only for the main pipeline
- Optional system tools for richer local evidence extraction: `pdftotext` and `tesseract` on `PATH`

If the optional OCR tools are unavailable, the agent still processes CSV, JSON, SQL, logs and text, but may miss facts embedded only in PDFs or screenshots.

## Run

From the repository root:

```bash
python code/main.py
```

The script reads `dataset/` relative to its own location, writes `output.csv` at the repository root, and validates the required header, row count, statuses, JSON schema, step numbering, and evidence-ID rules. A local `.audit_observations_cache.json` speeds up repeat runs; it is generated from the evidence files and is not part of `code.zip`.

## Evaluation

Run the public-sample comparison and additional synthetic unit tests:

```bash
python code/evaluation/main.py
python code/evaluation/custom_cases.py
```

The sample comparison uses `dataset/sample_output.csv` only for evaluation, never to generate predictions. The main prediction run reads `dataset/deletion_requests.csv` and participant-facing evidence only.

## Design limitations

Some resources are present in point-in-time exports without a direct subject identifier. The implementation uses request-aligned operational events only as a resource-discovery heuristic, then requires participant-visible evidence for the state. Where a resource-to-subject relationship is not explicit, the deterministic heuristic can still misassociate or miss a resource; see `evaluation/evaluation_report.md`. The public sample is used to measure and iteratively improve the approach, not to hardcode case IDs or output rows.

## Model and cost

No external model API is called. The audit pipeline is deterministic, so model calls, token usage and model API cost are zero. OCR tools run locally and are not token-based model calls.


## Accuracy caveat

This is a best-effort baseline, not a guaranteed perfect competition solution. The public sample reports status accuracy separately from exact step-array accuracy; resource-to-subject ambiguity remains the largest known weakness. Do not represent the generated predictions as 100% accurate or as a real-world legal deletion certificate. Run the sample evaluation and validator before submission.
