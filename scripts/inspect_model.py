import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import json
from transformers import AutoTokenizer, AutoModelForSequenceClassification

LOCAL_MODEL_PATH = "./model"

print("=" * 80)
print("THÔNG TIN CHI TIẾT MODEL")
print("=" * 80)

# Load model và tokenizer
tokenizer = AutoTokenizer.from_pretrained(LOCAL_MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(LOCAL_MODEL_PATH)

# 1. Thông tin cấu hình model
print("\n📋 CẤU HÌNH MODEL:")
print("-" * 80)
config = model.config
print(f"Model type: {config.model_type}")
print(f"Architecture: {config.architectures}")
print(f"Number of labels: {config.num_labels}")
print(f"Hidden size: {config.hidden_size}")
print(f"Number of layers: {config.num_hidden_layers}")
print(f"Number of attention heads: {config.num_attention_heads}")
print(f"Max position embeddings: {config.max_position_embeddings}")
print(f"Vocab size: {config.vocab_size}")

# 2. Label mapping
print("\n🏷️  LABEL MAPPING:")
print("-" * 80)
if hasattr(config, 'id2label') and config.id2label:
    for id, label in config.id2label.items():
        print(f"  {id}: {label}")
if hasattr(config, 'label2id') and config.label2id:
    print("\nLabel to ID:")
    for label, id in config.label2id.items():
        print(f"  {label}: {id}")

# 3. Tokenizer info
print("\n🔤 THÔNG TIN TOKENIZER:")
print("-" * 80)
print(f"Tokenizer type: {type(tokenizer).__name__}")
print(f"Vocab size: {len(tokenizer)}")
print(f"Model max length: {tokenizer.model_max_length}")
print(f"Special tokens:")
print(f"  - PAD: {tokenizer.pad_token} (ID: {tokenizer.pad_token_id})")
print(f"  - UNK: {tokenizer.unk_token} (ID: {tokenizer.unk_token_id})")
print(f"  - CLS: {tokenizer.cls_token} (ID: {tokenizer.cls_token_id})")
print(f"  - SEP: {tokenizer.sep_token} (ID: {tokenizer.sep_token_id})")
print(f"  - MASK: {tokenizer.mask_token} (ID: {tokenizer.mask_token_id})")

# 4. Model architecture
print("\n🏗️  KIẾN TRÚC MODEL:")
print("-" * 80)
print(model)

# 5. Tổng số parameters
print("\n📊 THỐNG KÊ PARAMETERS:")
print("-" * 80)
total_params = sum(p.numel() for p in model.parameters())
trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
print(f"Total parameters: {total_params:,}")
print(f"Trainable parameters: {trainable_params:,}")
print(f"Non-trainable parameters: {total_params - trainable_params:,}")

# 6. Chi tiết từng layer
print("\n🔍 CHI TIẾT PARAMETERS THEO LAYER:")
print("-" * 80)
for name, param in model.named_parameters():
    print(f"{name:60s} | Shape: {str(param.shape):30s} | {param.numel():,} params")

# 7. Config files trong thư mục
print("\n📁 FILES TRONG THƯ MỤC MODEL:")
print("-" * 80)
import os
for file in sorted(os.listdir(LOCAL_MODEL_PATH)):
    file_path = os.path.join(LOCAL_MODEL_PATH, file)
    size = os.path.getsize(file_path)
    size_mb = size / (1024 * 1024)
    print(f"  {file:40s} {size_mb:>10.2f} MB")

# 8. Nội dung config.json
print("\n⚙️  NỘI DUNG CONFIG.JSON:")
print("-" * 80)
config_path = os.path.join(LOCAL_MODEL_PATH, "config.json")
if os.path.exists(config_path):
    with open(config_path, 'r') as f:
        config_json = json.load(f)
    print(json.dumps(config_json, indent=2, ensure_ascii=False))

# 9. Test inference để xem output shape
print("\n🧪 TEST INFERENCE:")
print("-" * 80)
test_text = "Sample log message for testing"
inputs = tokenizer(test_text, return_tensors="pt", truncation=True, max_length=512)
print(f"Input IDs shape: {inputs['input_ids'].shape}")
print(f"Attention mask shape: {inputs['attention_mask'].shape}")

import torch
with torch.no_grad():
    outputs = model(**inputs)
    print(f"Logits shape: {outputs.logits.shape}")
    print(f"Logits values: {outputs.logits}")
    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
    print(f"Probabilities: {probs}")
    
print("\n" + "=" * 80)
print("✓ HOÀN THÀNH")
print("=" * 80)
