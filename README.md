# Cyberfortress ML Logs Classification

**Purpose:** Lightweight toolkit to normalize diverse security logs into concise text inputs and label them using a text-classification model. The primary target is Elasticsearch ingest pipelines (Painless + inference processor), but the repo also includes local utilities for inspection and offline testing.

**Status:** Production-ready pipeline logic for common security telemetry (Suricata, Zeek, pfSense, ModSecurity, Apache, Nginx, MySQL, Windows, Wazuh). Local tooling is provided for development and evaluation.

## **Quick Summary**
- **Repository:** Converts indexed logs into `ml.prediction.input` and runs a text classification model.
- **Primary script:** `ingest/scripts/bylastic-log-classifier.painless` (constructs classifier input).
- **Local CLI:** `classify_log.py` mirrors the Painless logic for offline testing.
- **Extraction helper:** `scripts/prepare_ml_ready.py` extracts ML-ready logs from Elasticsearch-style JSON into `logs/ML-Ready-Logs`.

## **Getting Started**
- **Requirements:**
  - **Python**: 3.8+
  - **Elasticsearch**: 8.x (for ingest pipeline + inference processor)
  - Optional for local inference: `transformers`, `torch`, `safetensors`
- **Install (local dev):**

```bash
python -m venv .venv
source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## **Quick Usage**
- Classify a single document (local):

```bash
python classify_log.py --input sample_log.json
# or pipe JSON
cat sample_log.json | python classify_log.py
```

- Extract ML-ready logs from an Elasticsearch hits file into `logs/ML-Ready-Logs`:

```bash
python scripts/prepare_ml_ready.py --input logs/ECS-Logs/suricata.json
```

The extractor writes `ml_ready.jsonl` and individual `doc_*.json` files into the output folder.

## **How It Works**
- **Painless script** (`ingest/scripts/bylastic-log-classifier.painless`):
  - Detects source index by substring (e.g., `suricata`, `zeek`, `nginx`).
  - Applies per-source rules to build a short, human-readable text describing the event.
  - Writes the result to `ctx.ml_input` (ingest) which maps to `ml.prediction.input` in the pipeline configuration.
- **Inference processor** (`ingest/pipelines/bylastic-log-classifier.json`):
  - Maps `ml.prediction.input` → model `text_field`.
  - Runs only when valid input exists.

## **Design Choices & Behavior**
- **Selective processing:** Only indices listed in the script's hit list are considered; noisy/common events (e.g., nginx notices, Suricata flows) are intentionally skipped.
- **Field handling:** The local tools accept both raw JSON logs and Elasticsearch hit documents (they flatten `fields.*` and parse `event.original` when present).
- **Output format:** Local classifier returns `{'ml': {'prediction': {'input': '...'}}}` for matched logs; the extractor attaches this under `_ml` in exported docs.

## **Troubleshooting**
- **No matches from extractor:** Confirm the input file contains events the Painless script treats as alerts (e.g., Suricata `event_type == 'alert'` with `rule.name`). Many ES datasets contain flows/protocol events that are intentionally skipped.
- **Stale `ml.prediction` in documents:** Either clear `ctx.ml` in the Painless script when skipping, or ensure earlier pipelines do not set `ml.prediction` prematurely.

## **Extending the Pipeline**
- **Add a source:** Add an `if` block in `ingest/scripts/bylastic-log-classifier.painless` and include the index substring in the `hit` list.
- **Change model:** Replace files in `model/` and update `bylastic-log-classifier.json` inference `model_id`. For local inference, update `inspect_model.py` with new artifact paths.

## **Files of Interest**
- **`ingest/scripts/bylastic-log-classifier.painless`**: Painless script building the input text.
- **`ingest/pipelines/bylastic-log-classifier.json`**: Ingest pipeline + inference config.
- **`classify_log.py`**: Local CLI replicating Painless logic.
- **`scripts/prepare_ml_ready.py`**: Pulls ML-ready docs from ES-formatted files.

## **Contributing**
- Fork, create a feature branch, and open a pull request. Include minimal example logs and unit tests for added parsing logic.

## **License**
- This project is licensed under the Apache License. See `LICENSE` for details.

---
If you want, I can also add a short `DEVNOTES.md` with developer tips (how to run the pipeline locally, test new Painless rules, and format sample ES hits). 

