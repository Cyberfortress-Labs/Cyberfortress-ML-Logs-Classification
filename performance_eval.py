import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import time
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 1. Load model
LOCAL_MODEL_PATH = "./model"
print(f"Loading model from {LOCAL_MODEL_PATH}...")
tokenizer = AutoTokenizer.from_pretrained(LOCAL_MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(LOCAL_MODEL_PATH)
model.eval()

# Move to GPU if available
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
print(f"Model loaded on {device}\n")

# 2. Prediction function (optimized for single log)
def predict_single(log_text):
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
    
    return predicted_class_id, confidence

# 3. Performance Evaluation
def evaluate_performance(log_file="logs/logs-test.log", num_iterations=1000):
    print(f"Reading logs from {log_file}...")
    
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            # Read all lines and filter empty ones
            logs = [line.strip() for line in f if line.strip()]
            
        if not logs:
            print("Error: Log file is empty!")
            return

        print(f"Loaded {len(logs)} unique log lines.")
        
    except FileNotFoundError:
        print(f"Error: File {log_file} not found!")
        return

    print(f"Starting performance evaluation with {num_iterations} iterations...")
    
    # Warmup
    print("Warming up...")
    for _ in range(10):
        predict_single(logs[0])
    
    latencies = []
    
    print("Benchmarking...")
    start_total = time.time()
    
    # Cycle through logs if num_iterations > len(logs)
    import itertools
    log_cycle = itertools.cycle(logs)
    
    for i in range(num_iterations):
        log_text = next(log_cycle)
        
        start_time = time.time()
        predict_single(log_text)
        end_time = time.time()
        latencies.append(end_time - start_time)
        
        if (i + 1) % (num_iterations // 10) == 0:
            print(f"Progress: {i + 1}/{num_iterations}")
            
    end_total = time.time()
    total_time = end_total - start_total
    
    # Calculate metrics
    avg_latency = np.mean(latencies)
    p50_latency = np.percentile(latencies, 50)
    p95_latency = np.percentile(latencies, 95)
    p99_latency = np.percentile(latencies, 99)
    throughput = num_iterations / total_time
    
    print("\n" + "="*40)
    print("PERFORMANCE RESULTS")
    print("="*40)
    print(f"Log Source: {log_file}")
    print(f"Total time: {total_time:.4f} seconds")
    print(f"Total logs processed: {num_iterations}")
    print(f"Throughput: {throughput:.2f} logs/second")
    print("-" * 40)
    print(f"Average Latency: {avg_latency * 1000:.4f} ms/log")
    print(f"P50 Latency:     {p50_latency * 1000:.4f} ms/log")
    print(f"P95 Latency:     {p95_latency * 1000:.4f} ms/log")
    print(f"P99 Latency:     {p99_latency * 1000:.4f} ms/log")
    print("="*40)

if __name__ == "__main__":
    # Check if numpy is installed, if not, use pure python for basic stats or warn
    try:
        import numpy as np
    except ImportError:
        print("Numpy not found. Installing...")
        import subprocess
        subprocess.check_call(["pip", "install", "numpy"])
        import numpy as np

    evaluate_performance()
