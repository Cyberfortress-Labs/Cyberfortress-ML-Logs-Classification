import argparse
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification


def download_and_save_model(model_name: str, model_dir: Path):
    print(f"[+] Downloading model: {model_name}")

    # Load tokenizer + model
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)

    # Create output directory
    model_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Saving model to: {model_dir.resolve()}")

    tokenizer.save_pretrained(model_dir)
    model.save_pretrained(model_dir)

    print("[✓] Model downloaded and saved successfully.")


def main():
    parser = argparse.ArgumentParser(
        description="Download HuggingFace model + tokenizer and save to directory."
    )

    parser.add_argument(
        "--model_dir",
        type=str,
        required=True,
        help="Directory to save the model (e.g., ./model)"
    )

    parser.add_argument(
        "--model_name",
        type=str,
        default="byviz/bylastic_classification_logs",
        help="Model name on HuggingFace (default: bylastic classification logs)"
    )

    args = parser.parse_args()

    model_path = Path(args.model_dir)
    download_and_save_model(args.model_name, model_path)


if __name__ == "__main__":
    main()
