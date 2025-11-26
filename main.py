import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import json
import time
from pathlib import Path
from collections import Counter
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# 1. Load model
LOCAL_MODEL_PATH = "./model"
MIN_LOG_LENGTH = 20
MAX_PREVIEW_LOGS = 1000000

print(f"Đang load model từ {LOCAL_MODEL_PATH}...")
tokenizer = AutoTokenizer.from_pretrained(LOCAL_MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(LOCAL_MODEL_PATH)
model.eval()
print("Model đã load thành công!\n")

# ============================
#  HÀM ĐO THỜI GIAN XỬ LÝ 1 LOG
# ============================
def classify_log_with_time(log_text):
    """Phân loại log + thời gian xử lý (ms)"""
    start = time.perf_counter()

    inputs = tokenizer(
        log_text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=False
    )

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        predicted_class_id = outputs.logits.argmax(dim=-1).item()
        confidence = probs[0][predicted_class_id].item()

    end = time.perf_counter()
    elapsed_ms = (end - start) * 1000  # ms

    return {
        "label": model.config.id2label[predicted_class_id],
        "confidence": f"{confidence * 100:.2f}%",
        "time_ms": elapsed_ms
    }

# ============================
#  Các hàm xử lý log
# ============================
LOG_FIELD_PRIORITY = [
    ["message"],
    ["event", "original"],
    ["_source", "message"],
    ["_source", "event", "original"],
    ["_source", "full_log"],
    ["log"],
]

def get_nested_value(data, keys):
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return None
    return data

def extract_log_from_dict(data):
    for path in LOG_FIELD_PRIORITY:
        value = get_nested_value(data, path)
        if value:
            return str(value)
    return json.dumps(data)

def extract_log_text(file_path):
    logs = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().strip()

        try:
            data = json.loads(content)
            if isinstance(data, dict):
                logs.append(extract_log_from_dict(data))
            elif isinstance(data, list):
                for item in data:
                    logs.append(extract_log_from_dict(item) if isinstance(item, dict) else str(item))
        except json.JSONDecodeError:
            logs.extend(line.strip() for line in content.split("\n") if line.strip())

    return logs

# ============================
#  MAIN: phân tích logs
# ============================
def analyze_logs(log_folder="logs", output_file="logs/classification_results.txt"):
    print(f"Đang quét thư mục: {log_folder}")

    log_path = Path(log_folder)
    log_files = list(log_path.glob("*.log")) + list(log_path.glob("*.json"))

    if not log_files:
        print("Không tìm thấy file log nào!")
        return

    print(f"Tìm thấy {len(log_files)} file(s)\n")

    all_results = []
    total_process_time = 0
    total_logs_counted = 0

    for log_file in log_files:
        print(f"Đang xử lý: {log_file.name}...")
        logs = extract_log_text(str(log_file))
        file_results = []

        for i, log_text in enumerate(logs, 1):
            if len(log_text) > MIN_LOG_LENGTH:

                result = classify_log_with_time(log_text)
                total_process_time += result["time_ms"]
                total_logs_counted += 1

                file_results.append({
                    "file": log_file.name,
                    "line": i,
                    "log": log_text,
                    "label": result["label"],
                    "confidence": result["confidence"],
                    "time_ms": f"{result['time_ms']:.2f} ms"
                })

                if i <= MAX_PREVIEW_LOGS:
                    print(f"  [{result['label']}] ({result['time_ms']:.2f} ms) {log_text[:80]}...")

        all_results.extend(file_results)
        print(f"  ✓ Đã phân loại {len(file_results)} log(s)\n")

    if not all_results:
        print("Không có log nào được phân loại!")
        return

    # ============================
    #  TỔNG HỢP
    # ============================
    print("=" * 80)
    print("THỐNG KÊ TỔNG HỢP:")
    print("=" * 80)

    label_counts = Counter(r["label"] for r in all_results)
    total_count = len(all_results)

    for label, count in label_counts.most_common():
        percent = (count / total_count) * 100
        print(f"{label}: {count} ({percent:.2f}%)")

    avg_time = total_process_time / total_logs_counted if total_logs_counted else 0
    print(f"\n📌 Tổng log xử lý: {total_logs_counted}")
    print(f"⏱️ Tổng thời gian xử lý: {total_process_time:.2f} ms")
    print(f"⚡ Thời gian trung bình / log: {avg_time:.2f} ms")

    # ============================
    #  GHI FILE
    # ============================
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("CLASSIFICATION RESULTS\n")
        f.write("=" * 80 + "\n\n")

        for r in all_results:
            f.write(f"File: {r['file']} | Line: {r['line']} | Label: [{r['label']}] | Time: {r['time_ms']}\n")
            f.write(f"Log: {r['log']}\n")
            f.write(f"Confidence: {r['confidence']}\n")
            f.write("-" * 80 + "\n")

    print(f"\n✓ Đã lưu {total_count} kết quả vào: {output_file}")

if __name__ == "__main__":
    analyze_logs()
