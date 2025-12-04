from transformers import AutoTokenizer, AutoModelForSequenceClassification
from pathlib import Path

MODEL_NAME = "byviz/bylastic_classification_logs"
OUTPUT_DIR = Path("./model")

def download_and_save_model():
    print(f"[+] Downloading model: {MODEL_NAME}")
    
    # Load tokenizer + model
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)

    # Create output folder
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[+] Saving model to: {OUTPUT_DIR.resolve()}")

    # Save tokenizer + model
    tokenizer.save_pretrained(OUTPUT_DIR)
    model.save_pretrained(OUTPUT_DIR)

    print("[✓] Model downloaded and saved successfully.")

if __name__ == "__main__":
    download_and_save_model()
