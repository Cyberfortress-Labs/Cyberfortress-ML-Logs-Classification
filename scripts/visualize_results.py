#!/usr/bin/env python3
import argparse
import json
import os
import matplotlib.pyplot as plt
import glob
from pathlib import Path

# ============================================================
# Helper: Ensure output directory exists
# ============================================================
def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def get_timestamp():
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ============================================================
# Visualization Functions
# ============================================================
def plot_class_distribution(labels, counts, output_dir):
    plt.figure(figsize=(7, 6))
    plt.bar(labels, counts, color=["orange", "green", "red"])
    plt.title("Class Distribution")
    plt.xlabel("Label")
    plt.ylabel("Count")
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f"class_distribution_{get_timestamp()}.png"))
    plt.close()


def plot_pie_distribution(labels, counts, output_dir):
    plt.figure(figsize=(7,7))
    plt.pie(
        counts, labels=labels, autopct="%1.1f%%",
        startangle=140, wedgeprops={"edgecolor": "black"}
    )
    plt.title("Prediction Label Distribution")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f"class_pie_{get_timestamp()}.png"))
    plt.close()


def plot_latency_box(latencies, output_dir):
    plt.figure(figsize=(6,6))
    plt.boxplot(latencies, vert=True, patch_artist=True,
                boxprops=dict(facecolor="lightblue"))
    plt.title("Latency Distribution (ms)")
    plt.ylabel("Latency (ms)")
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f"latency_box_{get_timestamp()}.png"))
    plt.close()


def plot_latency_line(latencies, output_dir):
    plt.figure(figsize=(12,6))
    plt.plot(latencies, linewidth=1)
    plt.title("Latency Over Logs")
    plt.xlabel("Log Index")
    plt.ylabel("Latency (ms)")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f"latency_line_{get_timestamp()}.png"))
    plt.close()


def plot_latency_hist(latencies, output_dir):
    plt.figure(figsize=(8,6))
    plt.hist(latencies, bins=40, color="steelblue", edgecolor="black")
    plt.title("Latency Histogram")
    plt.xlabel("Latency (ms)")
    plt.ylabel("Frequency")
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f"latency_hist_{get_timestamp()}.png"))
    plt.close()

def resolve_input_file(pattern: str):
    """Resolve wildcard pattern to the newest matching file."""
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError(f"No files matched pattern: {pattern}")

    # Sort by modified time, newest first
    files = sorted(files, key=lambda f: Path(f).stat().st_mtime, reverse=True)
    return files[0]

# ============================================================
# Main CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Visualize ML evaluation results"
    )

    parser.add_argument(
        "--input", required=True,
        help="Path to JSON evaluation result file"
    )
    parser.add_argument(
        "--output", required=True,
        help="Directory to store generated visualization images"
    )

    args = parser.parse_args()
    input_path = resolve_input_file(args.input)
    print(f"[OK] Using latest file: {input_path}")
    
    output_dir = args.output

    # Make sure output directory exists
    ensure_dir(output_dir)

    # Load data
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    stats = data["statistics"]
    results = data["results"]

    # Extract distributions
    label_dist = stats["label_distribution"]
    labels = list(label_dist.keys())
    counts = list(label_dist.values())

    # Extract latency list
    latencies = [item["latency_ms"] for item in results]

    print("[+] Generating visualization...")

    # Generate plots
    plot_class_distribution(labels, counts, output_dir)
    plot_pie_distribution(labels, counts, output_dir)
    plot_latency_box(latencies, output_dir)
    plot_latency_line(latencies, output_dir)
    plot_latency_hist(latencies, output_dir)

    print(f"[✓] Visualization completed. Files saved to: {output_dir}")


if __name__ == "__main__":
    main()
