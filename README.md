Dưới đây là phiên bản **README chuẩn GitHub**, đã **bổ sung rõ nguồn model HuggingFace**, ghi chú rằng **model không phải do bạn train**, bạn chỉ sử dụng.

---

# Cyberfortress ML Logs Classification

## Purpose

Lightweight pipeline and model integration that converts diverse security logs into normalized text inputs and applies a text-classification model to label events (INFO, WARNING, ALERT, etc.).
Designed primarily for Elasticsearch ingest pipelines but includes local utilities for inspection and evaluation.

## Model Source

This project uses the publicly available model:

**HuggingFace:** [https://huggingface.co/byviz/bylastic_classification_logs](https://huggingface.co/byviz/bylastic_classification_logs)

The model is developed and published by **byviz**.
It is **not trained by this repository**; this project only integrates and utilizes it inside Elasticsearch or local tooling.

## Overview

**What it does:**
Normalizes and filters logs from multiple sources (Suricata, Zeek, pfSense, ModSecurity, Apache, Nginx, MySQL, Windows, Wazuh), constructs a concise text description of each event, and applies a text-classification model to generate `ml.prediction`.

**Key design choices:**

* Per-source parsing logic implemented in `bylastic-log-classifier.painless`.
* Uses a consistent inference input field: `ml.prediction.input`.
* Inference processor configuration stored in `bylastic-log-classifier.json`.

## Repository Layout

```
ingest/
  pipelines/bylastic-log-classifier.json      # Ingest pipeline with script + inference processor
  scripts/bylastic-log-classifier.painless  # Painless script constructing classifier text input
  config-model.http                 # Example HTTP config (if present)

model/
  model.safetensors
  config.json
  special_tokens_map.json
  tokenizer_config.json
  tokenizer.json
  vocab.txt

logs/
  classification_results.txt        # Example output
  logs-test.log                     # Example input logs

inspect_model.py                    # Local model inspection utility
performance_eval.py                 # Evaluation scripts
main.py                             # Optional runner
```

## Requirements

* Python 3.8+ (for local tooling)
* Elasticsearch 8.x (for ingest pipeline + inference processor)
* ML libraries if running inference locally:

  * `transformers`
  * `torch`
  * `safetensors`
    (See `inspect_model.py` for exact imports.)

## Quick Setup (Local Inspection and Tests)

Create a virtual environment and install packages:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Inspect the model:

```bash
python inspect_model.py
```

Run evaluation (requires test dataset):

```bash
python performance_eval.py
```

## Ingest Pipeline Notes

* The Painless script writes classifier input to `ml_input`.
* Inference processor uses:

  * a `field_map` mapping `ml_input` → the model’s `text_field`,
  * an `if` condition ensuring valid input before inference runs.

To modify behavior:

* Update `bylastic-log-classifier.painless` for input construction.
* Update `bylastic-log-classifier.json` for mapping or logic changes.

## Behavior and Troubleshooting

* Only indices matched via substring-based checks in the script’s `hit` list are processed.
* Some noisy events (e.g., low-value nginx notices) are intentionally skipped.
* Existing `ml.prediction` fields are preserved unless the script explicitly overwrites them.

To avoid inaccurate/stale predictions:

* Clear `ctx.ml_input` when skipping irrelevant logs, or
* Ensure earlier pipelines do not produce `ml.prediction`.

Fallback behavior:

* If no source matches, the script uses `message` or `event.original` as generic input.

## Deploying the Ingest Pipeline to Elasticsearch

Example command:

```bash
curl -X PUT "http://localhost:9200/_ingest/pipeline/bylastic-log-classifier" \
  -H 'Content-Type: application/json' \
  -d @ingest/pipelines/bylastic-log-classifier.json
```

Reference this pipeline via index templates or client-side configuration.

## Evaluation and Metrics

Use `performance_eval.py` to compute precision, recall, F1, or custom metrics.
Modify the script to match your dataset format.

## Extending / Customizing

* Add a new log source:
  Extend `bylastic-log-classifier.painless` with a new parsing block and include its index substring in the `hit` list.
* Change model:
  Replace contents in `model/` and update the Elasticsearch inference model with a matching `model_id`.
  For local inference, point scripts to the new artifacts.

## Contributing

Fork the repository, create a feature branch, and submit a pull request.
Keep changes focused and include minimal example logs under `logs/` when appropriate.

## License
This project is licensed under the Apache License. See the [LICENSE](LICENSE) file for details.

