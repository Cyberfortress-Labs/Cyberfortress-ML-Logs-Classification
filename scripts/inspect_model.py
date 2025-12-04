import os
import json
import argparse
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


def inspect_model(model_dir: Path, output_res: Path):
    # Create output folder
    output_res.mkdir(parents=True, exist_ok=True)

    # Output file paths
    info_file = output_res / "model_info.txt"
    params_file = output_res / "parameters.txt"
    config_copy = output_res / "config.json"

    # Begin console output
    print("=" * 80)
    print("MODEL INSPECTION REPORT")
    print("=" * 80)

    # Load tokenizer + model
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)

    # Collect report text
    report_lines = []

    report_lines.append("=" * 80)
    report_lines.append("MODEL CONFIGURATION")
    report_lines.append("=" * 80)

    config = model.config
    report_lines.append(f"Model type: {config.model_type}")
    report_lines.append(f"Architecture: {config.architectures}")
    report_lines.append(f"Number of labels: {config.num_labels}")
    report_lines.append(f"Hidden size: {config.hidden_size}")
    report_lines.append(f"Number of layers: {config.num_hidden_layers}")
    report_lines.append(f"Attention heads: {config.num_attention_heads}")
    report_lines.append(f"Max position embeddings: {config.max_position_embeddings}")
    report_lines.append(f"Vocab size: {config.vocab_size}")

    # Label mapping
    report_lines.append("\nLABEL MAPPING")
    report_lines.append("-" * 80)

    if hasattr(config, 'id2label'):
        for id, label in config.id2label.items():
            report_lines.append(f"ID {id}: {label}")

    if hasattr(config, 'label2id'):
        report_lines.append("\nLabel to ID:")
        for label, id in config.label2id.items():
            report_lines.append(f"{label}: {id}")

    # Tokenizer info
    report_lines.append("\nTOKENIZER INFORMATION")
    report_lines.append("-" * 80)
    report_lines.append(f"Tokenizer class: {type(tokenizer).__name__}")
    report_lines.append(f"Vocab size: {len(tokenizer)}")
    report_lines.append(f"Model max length: {tokenizer.model_max_length}")
    report_lines.append("Special tokens:")
    report_lines.append(f"  PAD:  {tokenizer.pad_token} (ID {tokenizer.pad_token_id})")
    report_lines.append(f"  UNK:  {tokenizer.unk_token} (ID {tokenizer.unk_token_id})")
    report_lines.append(f"  CLS:  {tokenizer.cls_token} (ID {tokenizer.cls_token_id})")
    report_lines.append(f"  SEP:  {tokenizer.sep_token} (ID {tokenizer.sep_token_id})")
    report_lines.append(f"  MASK: {tokenizer.mask_token} (ID {tokenizer.mask_token_id})")

    # Model architecture summary
    report_lines.append("\nMODEL ARCHITECTURE")
    report_lines.append("-" * 80)
    report_lines.append(str(model))

    # Parameter statistics
    report_lines.append("\nPARAMETER STATISTICS")
    report_lines.append("-" * 80)

    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

    report_lines.append(f"Total parameters: {total_params:,}")
    report_lines.append(f"Trainable parameters: {trainable_params:,}")
    report_lines.append(f"Non-trainable parameters: {total_params - trainable_params:,}")

    # File listing
    report_lines.append("\nFILES IN MODEL DIRECTORY")
    report_lines.append("-" * 80)

    for file in sorted(os.listdir(model_dir)):
        file_path = model_dir / file
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        report_lines.append(f"{file:40s} {size_mb:10.2f} MB")

    # Inference test
    report_lines.append("\nINFERENCE TEST")
    report_lines.append("-" * 80)

    test_text = "Sample log message for testing"
    inputs = tokenizer(test_text, return_tensors="pt", truncation=True, max_length=512)

    report_lines.append(f"Input IDs shape: {inputs['input_ids'].shape}")
    report_lines.append(f"Attention mask shape: {inputs['attention_mask'].shape}")

    with torch.no_grad():
        outputs = model(**inputs)
        report_lines.append(f"Logits shape: {outputs.logits.shape}")
        report_lines.append(f"Logits: {outputs.logits}")
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        report_lines.append(f"Probabilities: {probs}")

    # Write main info file
    info_file.write_text("\n".join(report_lines), encoding="utf-8")

    # Write layer-by-layer parameters
    with open(params_file, "w", encoding="utf-8") as pf:
        for name, param in model.named_parameters():
            pf.write(f"{name:60s} | Shape: {str(param.shape):25s} | Params: {param.numel():,}\n")

    # Copy config.json
    config_json_path = model_dir / "config.json"
    if config_json_path.exists():
        with open(config_json_path, "r", encoding="utf-8") as src, \
             open(config_copy, "w", encoding="utf-8") as dst:
            dst.write(src.read())

    print("=" * 80)
    print("INSPECTION COMPLETED")
    print(f"Results saved to: {output_res}")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Inspect a HuggingFace model")
    parser.add_argument("--model_dir", type=str, required=True,
                        help="Local directory of the model")
    parser.add_argument("--output_res", type=str, required=True,
                        help="Directory to save the inspection result files")
    args = parser.parse_args()

    inspect_model(Path(args.model_dir), Path(args.output_res))


if __name__ == "__main__":
    main()
