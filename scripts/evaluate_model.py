"""
ML Model Evaluator
Read logs with ml_input field, predict with model, save results
Supports multi-processing for faster evaluation
"""

import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import json
import time
import torch
import numpy as np
import sys
from pathlib import Path
from datetime import datetime
from multiprocessing import Pool, cpu_count
from transformers import AutoTokenizer, AutoModelForSequenceClassification


# Global variables for multiprocessing
tokenizer = None
model = None
device = None

# Label mapping
LABEL_MAP = {
    0: "ERROR",
    1: "WARNING", 
    2: "INFO"
}

LABEL_DESCRIPTIONS = {
    "ERROR": "Critical failures or serious problems requiring immediate attention",
    "WARNING": "Potential issues that could become errors if not properly managed",
    "INFO": "Informational logs about normal system functioning"
}


def init_worker(model_path):
    """Initialize model in each worker process"""
    global tokenizer, model, device
    
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    model.eval()
    
    # Use CPU for worker processes (GPU sharing in multiprocessing is complex)
    device = torch.device("cpu")
    model.to(device)


def predict_single(log_text):
    """Predict single log entry"""
    global tokenizer, model, device
    
    try:
        inputs = tokenizer(
            log_text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=False
        ).to(device)
        
        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            predicted_class_id = outputs.logits.argmax(dim=-1).item()
            confidence = probs[0][predicted_class_id].item()
        
        return {
            'predicted_class': predicted_class_id,
            'predicted_label': LABEL_MAP.get(predicted_class_id, "UNKNOWN"),
            'confidence': confidence,
            'success': True,
            'error': None
        }
    
    except Exception as e:
        return {
            'predicted_class': -1,
            'predicted_label': "ERROR_PREDICTION",
            'confidence': 0.0,
            'success': False,
            'error': str(e)
        }


def predict_batch(args):
    """Predict a batch of logs (for multiprocessing)"""
    idx, log_text = args
    start_time = time.time()
    result = predict_single(log_text)
    latency = time.time() - start_time
    
    return {
        'index': idx,
        'ml_input': log_text,
        'predicted_class': result['predicted_class'],
        'predicted_label': result['predicted_label'],
        'confidence': result['confidence'],
        'latency_ms': latency * 1000,
        'success': result['success'],
        'error': result['error']
    }


def parse_log_line(line):
    """Parse log line to extract ml_input field"""
    line = line.strip()
    
    # Format: ml_input : <text>
    if line.startswith('ml_input'):
        parts = line.split(':', 1)
        if len(parts) == 2:
            return parts[1].strip()
    
    # Fallback: treat entire line as ml_input
    return line


def read_input_file(input_file):
    """Read input file and extract ml_input fields"""
    logs = []
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            ml_input = parse_log_line(line)
            if ml_input:
                logs.append({
                    'line_num': line_num,
                    'ml_input': ml_input
                })
    
    return logs


def evaluate_model(
    input_file,
    output_dir='results',
    model_path='./model',
    num_workers=5,
    batch_size=100
):
    """
    Evaluate model on input logs
    
    Args:
        input_file: Input text file with ml_input fields
        output_dir: Output directory for results
        model_path: Path to model directory
        num_workers: Number of CPU workers for parallel processing
        batch_size: Batch size for progress reporting
    """
    
    # Validate inputs
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"[X] Error: Input file not found: {input_file}")
        sys.exit(1)
    
    if not Path(model_path).exists():
        print(f"[X] Error: Model not found: {model_path}")
        sys.exit(1)
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Generate output filenames with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    input_basename = input_path.stem
    output_json = output_path / f"{input_basename}_{timestamp}.json"
    output_txt = output_path / f"{input_basename}_{timestamp}.txt"
    
    print("=" * 70)
    print("ML MODEL EVALUATOR")
    print("=" * 70)
    print(f"Input file:    {input_path.absolute()}")
    print(f"Model path:    {Path(model_path).absolute()}")
    print(f"Output dir:    {output_path.absolute()}")
    print(f"CPU workers:   {num_workers}")
    print(f"Device:        CPU (multi-processing)")
    print("=" * 70)
    print()
    
    # Read input logs
    print("Reading input file...")
    logs = read_input_file(input_path)
    
    if not logs:
        print("[X] Error: No valid ml_input entries found in input file")
        sys.exit(1)
    
    print(f"[OK] Loaded {len(logs)} log entries")
    print()
    
    # Prepare data for multiprocessing
    log_data = [(i, log['ml_input']) for i, log in enumerate(logs)]
    
    # Start evaluation
    print(f"Starting evaluation with {num_workers} workers...")
    print("=" * 70)
    
    start_time = time.time()
    results = []
    
    # Use multiprocessing pool
    with Pool(processes=num_workers, initializer=init_worker, initargs=(model_path,)) as pool:
        # Process in batches for progress reporting
        for i, result in enumerate(pool.imap(predict_batch, log_data, chunksize=10), 1):
            results.append(result)
            
            # Progress reporting
            if i % batch_size == 0 or i == len(logs):
                elapsed = time.time() - start_time
                speed = i / elapsed
                eta = (len(logs) - i) / speed if speed > 0 else 0
                print(f"Progress: {i}/{len(logs)} ({i/len(logs)*100:.1f}%) | "
                      f"Speed: {speed:.1f} logs/s | ETA: {eta:.1f}s")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print("=" * 70)
    print()
    
    # Calculate statistics
    successful = [r for r in results if r['success']]
    failed = [r for r in results if not r['success']]
    
    latencies = [r['latency_ms'] for r in successful]
    
    if latencies:
        avg_latency = np.mean(latencies)
        p50_latency = np.percentile(latencies, 50)
        p95_latency = np.percentile(latencies, 95)
        p99_latency = np.percentile(latencies, 99)
        min_latency = np.min(latencies)
        max_latency = np.max(latencies)
    else:
        avg_latency = p50_latency = p95_latency = p99_latency = 0
        min_latency = max_latency = 0
    
    throughput = len(logs) / total_time
    
    # Count predictions by class and label
    class_counts = {}
    label_counts = {}
    for r in successful:
        class_id = r['predicted_class']
        label = r['predicted_label']
        class_counts[class_id] = class_counts.get(class_id, 0) + 1
        label_counts[label] = label_counts.get(label, 0) + 1
    
    # Prepare summary
    summary = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'input_file': str(input_path.absolute()),
            'model_path': str(Path(model_path).absolute()),
            'num_workers': num_workers,
            'label_mapping': LABEL_MAP,
            'label_descriptions': LABEL_DESCRIPTIONS
        },
        'statistics': {
            'total_logs': len(logs),
            'successful': len(successful),
            'failed': len(failed),
            'total_time_seconds': total_time,
            'throughput_logs_per_second': throughput,
            'latency': {
                'avg_ms': avg_latency,
                'min_ms': min_latency,
                'max_ms': max_latency,
                'p50_ms': p50_latency,
                'p95_ms': p95_latency,
                'p99_ms': p99_latency
            },
            'class_distribution': class_counts,
            'label_distribution': label_counts
        },
        'results': results
    }
    
    # Save JSON results
    print("Saving results...")
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[OK] JSON results saved to: {output_json}")
    
    # Save TXT summary
    with open(output_txt, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("ML MODEL EVALUATION RESULTS\n")
        f.write("=" * 70 + "\n")
        f.write(f"Timestamp:     {summary['metadata']['timestamp']}\n")
        f.write(f"Input file:    {summary['metadata']['input_file']}\n")
        f.write(f"Model path:    {summary['metadata']['model_path']}\n")
        f.write(f"CPU workers:   {summary['metadata']['num_workers']}\n")
        f.write("\n")
        f.write("-" * 70 + "\n")
        f.write("STATISTICS\n")
        f.write("-" * 70 + "\n")
        f.write(f"Total logs:    {summary['statistics']['total_logs']}\n")
        f.write(f"Successful:    {summary['statistics']['successful']}\n")
        f.write(f"Failed:        {summary['statistics']['failed']}\n")
        f.write(f"Total time:    {summary['statistics']['total_time_seconds']:.2f} seconds\n")
        f.write(f"Throughput:    {summary['statistics']['throughput_logs_per_second']:.2f} logs/second\n")
        f.write("\n")
        f.write("-" * 70 + "\n")
        f.write("LATENCY\n")
        f.write("-" * 70 + "\n")
        f.write(f"Average:       {summary['statistics']['latency']['avg_ms']:.2f} ms\n")
        f.write(f"Min:           {summary['statistics']['latency']['min_ms']:.2f} ms\n")
        f.write(f"Max:           {summary['statistics']['latency']['max_ms']:.2f} ms\n")
        f.write(f"P50:           {summary['statistics']['latency']['p50_ms']:.2f} ms\n")
        f.write(f"P95:           {summary['statistics']['latency']['p95_ms']:.2f} ms\n")
        f.write(f"P99:           {summary['statistics']['latency']['p99_ms']:.2f} ms\n")
        f.write("\n")
        f.write("-" * 70 + "\n")
        f.write("LABEL CATEGORIES\n")
        f.write("-" * 70 + "\n")
        for label, desc in LABEL_DESCRIPTIONS.items():
            f.write(f"{label}:\n")
            f.write(f"  {desc}\n")
        f.write("\n")
        f.write("-" * 70 + "\n")
        f.write("PREDICTION DISTRIBUTION\n")
        f.write("-" * 70 + "\n")
        for label in ["ERROR", "WARNING", "INFO"]:
            count = label_counts.get(label, 0)
            percentage = count / len(successful) * 100 if successful else 0
            f.write(f"{label:10s} {count:6d} ({percentage:5.1f}%)\n")
        f.write("\n")
        f.write("-" * 70 + "\n")
        f.write("CLASS DISTRIBUTION\n")
        f.write("-" * 70 + "\n")
        for class_id, count in sorted(class_counts.items()):
            label = LABEL_MAP.get(class_id, "UNKNOWN")
            percentage = count / len(successful) * 100
            f.write(f"Class {class_id} ({label:7s}): {count:6d} ({percentage:5.1f}%)\n")
        f.write("\n")
        
        if failed:
            f.write("-" * 70 + "\n")
            f.write("FAILED PREDICTIONS\n")
            f.write("-" * 70 + "\n")
            for r in failed[:10]:  # Show first 10 failures
                f.write(f"Line {logs[r['index']]['line_num']}: {r['error']}\n")
            if len(failed) > 10:
                f.write(f"... and {len(failed) - 10} more failures\n")
        
        f.write("=" * 70 + "\n")
    
    print(f"[OK] TXT summary saved to: {output_txt}")
    print()
    
    # Print summary to console
    print("=" * 70)
    print("EVALUATION SUMMARY")
    print("=" * 70)
    print(f"Total logs:    {len(logs)}")
    print(f"Successful:    {len(successful)} ({len(successful)/len(logs)*100:.1f}%)")
    print(f"Failed:        {len(failed)} ({len(failed)/len(logs)*100:.1f}%)")
    print(f"Total time:    {total_time:.2f} seconds")
    print(f"Throughput:    {throughput:.2f} logs/second")
    print()
    print(f"Avg latency:   {avg_latency:.2f} ms")
    print(f"P95 latency:   {p95_latency:.2f} ms")
    print(f"P99 latency:   {p99_latency:.2f} ms")
    print()
    print("Prediction distribution:")
    for label in ["ERROR", "WARNING", "INFO"]:
        count = label_counts.get(label, 0)
        percentage = count / len(successful) * 100 if successful else 0
        print(f"  {label:10s} {count:6d} ({percentage:5.1f}%)")
    print()
    print("Class distribution:")
    for class_id, count in sorted(class_counts.items()):
        label = LABEL_MAP.get(class_id, "UNKNOWN")
        percentage = count / len(successful) * 100
        print(f"  Class {class_id} ({label:7s}): {count:6d} ({percentage:5.1f}%)")
    print("=" * 70)


def main():
    """Main function with command line interface"""
    
    if len(sys.argv) < 2:
        print("""
ML Model Evaluator - Predict logs with trained model

Usage:
    python evaluate_model.py <input_file> [num_workers] [output_dir] [model_path]

Arguments:
    input_file   Input text file with ml_input fields (required)
    num_workers  Number of CPU workers (default: 5)
    output_dir   Output directory (default: results)
    model_path   Path to model directory (default: ./model)

Examples:
    # Use defaults (5 workers)
    python evaluate_model.py assets/eval_input/eval_data.txt
    
    # Custom number of workers
    python evaluate_model.py assets/eval_input/eval_data.txt 10
    
    # Custom output directory
    python evaluate_model.py assets/eval_input/eval_data.txt 5 assets/eval_results
    
    # Full customization
    python evaluate_model.py assets/eval_input/eval_data.txt 8 assets/eval_results ./my_model

Note:
    - Input file format: Each line should have "ml_input : <text>"
    - Available CPUs: {cpu_count()}
""")
        sys.exit(1)
    
    # Parse arguments
    input_file = sys.argv[1]
    num_workers = int(sys.argv[2]) if len(sys.argv) >= 3 else 5
    output_dir = sys.argv[3] if len(sys.argv) >= 4 else 'results'
    model_path = sys.argv[4] if len(sys.argv) >= 5 else './model'
    
    # Validate num_workers
    max_workers = cpu_count()
    if num_workers > max_workers:
        print(f"[!] Warning: Requested {num_workers} workers, but only {max_workers} CPUs available")
        print(f"[!] Using {max_workers} workers instead")
        num_workers = max_workers
    
    try:
        evaluate_model(
            input_file=input_file,
            output_dir=output_dir,
            model_path=model_path,
            num_workers=num_workers
        )
        
        print("\n[OK] Evaluation completed successfully!")
        sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n\n[!] Evaluation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[X] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()