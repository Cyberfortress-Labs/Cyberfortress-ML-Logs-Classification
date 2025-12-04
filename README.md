
# **Cyberfortress Machine Learning Logs Classification**

A machine-learning–powered log classification system designed to normalize multi-source security logs (Suricata, Zeek, pfSense, ModSecurity, Apache, Nginx, MySQL, Windows, Wazuh, etc.) and predict their severity level: **ERROR**, **WARNING**, or **INFO**.



## **Installation**

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```



## **Workflow Overview**

(See `main.ipynb` for the full pipeline)

```bash
# 1. Download the model
python scripts/get_model.py --model_dir ./model

# 2. Inspect the model
python scripts/inspect_model.py --model_dir ./model --output_res ./inspect

# 3. Normalize logs (ECS logs → ML-ready logs)
python scripts/prepare_ml_ready.py assets/eval_logs/ecs_logs assets/eval_logs/processed_logs

# 4. Extract ML input text file
python scripts/extract_logs_for_ml.py assets/eval_logs/processed_logs assets/eval_input/eval_data.txt --simple-txt

# 5. Run inference evaluation
python scripts/evaluate_model.py assets/eval_input/eval_data.txt 12 assets/eval_results

# 6. Visualize results
python scripts/visualize_results.py --input assets/eval_results/eval_eval_data_20251204_162317.json --output assets/eval_charts
```


## **Project Structure**

```
ingest/                 # Elasticsearch ingest pipeline + Painless script
  pipelines/            # bylastic-log-classifier.json
  scripts/              # bylastic-log-classifier.painless

model/                  # Downloaded model artifacts (safetensors, config, tokenizer)

scripts/
  prepare_ml_ready.py        # Convert ECS → ML-ready logs
  extract_logs_for_ml.py     # Consolidate ml_input fields
  evaluate_model.py          # Run inference
  visualize_results.py       # Plot evaluation charts
  inspect_model.py           # Model metadata inspection
  get_model.py               # Download HF model

assets/
  eval_logs/
    ecs_logs/               # Raw ECS logs (Suricata, Zeek, etc.)
    processed_logs/         # Normalized logs for ML
  eval_input/               # Plain-text model input
  eval_results/             # Inference results (JSON)
  eval_charts/              # Visualization output
```



## **Elasticsearch Integration**

For detailed documentation, refer to:
https://www.elastic.co/docs/reference/elasticsearch/clients/eland/machine-learning#ml-nlp-pytorch-docker

Eland provides a command-line interface that allows you to **import HuggingFace PyTorch NLP models directly into Elasticsearch**, enabling built-in inference (text classification, embeddings, etc.) without needing an external ML service.

Below is an example command demonstrating how to import a model into Elasticsearch using `eland_import_hub_model`.
All credentials are replaced with placeholders:

```bash
eland_import_hub_model \
  --url https://<ELASTICSEARCH_HOST>:9200 \
  --es-username <USERNAME> \
  --es-password "<PASSWORD>" \
  --hub-model-id byviz/bylastic_classification_logs \
  --task-type text_classification \
  --start \
  --insecure \ # Use this flag if you have self-signed SSL certificates
```

### What this command does

* Connects to your Elasticsearch instance
* Downloads the HuggingFace model `byviz/bylastic_classification_logs`
* Converts it to an Elasticsearch-compatible format
* Creates and registers the model under the ML Inference API
* Starts the model so it can be used in ingest pipelines, search pipelines, or `_infer` APIs



## **Model Information**

* **Model:** `byviz/bylastic_classification_logs` (HuggingFace)
* **Output labels:** `ERROR` | `WARNING` | `INFO`
* **Input:** Normalized logs processed by the Painless script + ML preprocessing pipeline



## **License**

See `LICENSE` file for details.

