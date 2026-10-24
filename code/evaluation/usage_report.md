# Token Usage and Cost Report

## Final full-dataset run

- Run command: `python code/main.py`
- Requests processed: **518**
- Output rows written: **518**
- External LLM provider: **None**
- External model name: **None**
- External model calls: **0**
- Input tokens: **0**
- Output tokens: **0**
- Total tokens: **0**
- Average tokens per request: **0.0**
- Estimated model API cost: **$0.00 total**
- Estimated model API cost per request: **$0.00**

## Method

The full-dataset pipeline is deterministic Python code using the standard library, SQLite parsing, and optional local `pdftotext` / `tesseract` executables for local evidence extraction. It does not call an LLM API, send evidence to a model provider, or incur token-based model usage. Local CPU execution and optional OCR are not counted as model tokens or model API cost.

No API keys, credentials, or sensitive configuration values are included in the submission.
