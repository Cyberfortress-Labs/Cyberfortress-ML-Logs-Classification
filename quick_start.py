import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import torch
import time
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from multiprocessing import cpu_count


LABEL_MAP = {
    0: "ERROR",
    1: "WARNING",
    2: "INFO"
}


def load_model(model_dir="./model", workers=1):
    print("Loading model... (workers = %d)" % workers)

    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    model.eval()

    # Real-time inference always runs on CPU (no multiprocessing)
    device = torch.device("cpu")
    model.to(device)

    print("Model loaded successfully.\n")
    return tokenizer, model, device



def predict(text, tokenizer, model, device):
    start = time.perf_counter()

    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512
    ).to(device)

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)

    latency_ms = (time.perf_counter() - start) * 1000

    class_id = probs.argmax(dim=-1).item()
    confidence = probs[0][class_id].item()

    return LABEL_MAP[class_id], confidence, latency_ms



def main():
    import argparse

    parser = argparse.ArgumentParser(description="Interactive ML Log Classifier")
    parser.add_argument("--model_dir", type=str, default="./model", help="Path to model directory")
    parser.add_argument("--workers", type=int, default=1, help="Number of CPU workers to reserve (default=1)")
    args = parser.parse_args()

    # Validate worker count
    max_cpus = cpu_count()
    if args.workers < 1:
        args.workers = 1
    if args.workers > max_cpus:
        print(f"Requested {args.workers} workers, but only {max_cpus} available. Using {max_cpus}.")
        args.workers = max_cpus

    tokenizer, model, device = load_model(args.model_dir, args.workers)

    print("=== Cyberfortress Interactive Log Classifier ===")
    print("Type a log message and press Enter.")
    print("Type 'exit', 'quit', or 'q' to stop.\n")

    try:
        while True:
            user_input = input("Log > ").strip()

            if user_input.lower() in ["exit", "quit", "q"]:
                print("Exiting...")
                break

            if not user_input:
                continue

            label, conf, latency = predict(user_input, tokenizer, model, device)

            print("\nPrediction:")
            print(f"  Label      : {label}")
            print(f"  Confidence : {conf:.4f}")
            print(f"  Latency    : {latency:.2f} ms")
            print("-" * 50)

    except KeyboardInterrupt:
        print("\nInterrupted. Exiting safely...")
        return



if __name__ == "__main__":
    main()
