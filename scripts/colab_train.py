"""
QLoRA Fine-tuning Script for Llama 3.1 8B
Run this in Google Colab with T4 or A100 GPU.

Steps:
1. tar -czf training_data.tar.gz train.jsonl val.jsonl
2. Upload to Colab
3. Run this script
4. Download the GGUF adapter for Ollama deployment
"""
# %% [markdown]
# # QLoRA Fine-tune Llama 3.1 8B for 1-grid Support
# This notebook fine-tunes Llama 3.1 8B Instruct on 1-grid support conversations.

# %% [code]
# Install dependencies
!pip install -q accelerate peft bitsandbytes transformers trl datasets torch xformers

import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer
import json, os

# %% [code]
# Configuration
MODEL_NAME = "meta-llama/Meta-Llama-3.1-8B-Instruct"
OUTPUT_DIR = "./llama-3.1-8b-1grid-support"
DATASET_PATH = "./training_data"  # contains train.jsonl and val.jsonl

# %% [code]
# Load dataset
def format_example(example):
    return {
        "text": f"<|start_header_id|>user<|end_header_id|>\n\n{example['instruction']}\n{example['input']}<|eot_id|>\n<|start_header_id|>assistant<|end_header_id|>\n\n{example['output']}<|eot_id|>"
    }

train_data = []
val_data = []
with open(f"{DATASET_PATH}/train.jsonl") as f:
    for line in f:
        train_data.append(format_example(json.loads(line.strip())))
with open(f"{DATASET_PATH}/val.jsonl") as f:
    for line in f:
        val_data.append(format_example(json.loads(line.strip())))

with open("/tmp/train.json", "w") as f:
    json.dump(train_data, f)
with open("/tmp/val.json", "w") as f:
    json.dump(val_data, f)

dataset = load_dataset("json", data_files={"/tmp/train.json": "/tmp/train.json", "/tmp/val.json": "/tmp/val.json"})

# %% [code]
# 4-bit quantization config
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

# Load model
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
    use_cache=False,
)

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

# %% [code]
# LoRA config
peft_config = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
)

model = prepare_model_for_kbit_training(model)
model = get_peft_model(model, peft_config)

# %% [code]
# Training arguments
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=4,
    gradient_accumulation_steps=4,
    num_train_epochs=3,
    learning_rate=2e-4,
    fp16=True,
    logging_steps=10,
    evaluation_strategy="steps",
    eval_steps=50,
    save_strategy="steps",
    save_steps=100,
    save_total_limit=2,
    load_best_model_at_end=True,
    report_to="none",
    remove_unused_columns=False,
    dataloader_pin_memory=False,
)

# %% [code]
trainer = SFTTrainer(
    model=model,
    args=training_args,
    train_dataset=dataset["/tmp/train.json"],
    eval_dataset=dataset["/tmp/val.json"],
    tokenizer=tokenizer,
    max_seq_length=2048,
    dataset_text_field="text",
)

# %% [code]
# Train
trainer.train()

# %% [code]
# Save adapter
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

# %% [code]
# Convert to GGUF for Ollama (requires llama.cpp)
# After training, on Colab:
# !git clone https://github.com/ggerganov/llama.cpp
# !cd llama.cpp && make -j
# !python llama.cpp/convert_hf_to_gguf.py {OUTPUT_DIR} --outfile ./llama-3.1-8b-1grid.gguf
# !zip llama-3.1-8b-1grid.gguf.zip ./llama-3.1-8b-1grid.gguf
# Then download the zip and upload to VPS:
#   ollama create 1grid-support -f Modelfile
print(f"Training complete. Adapter saved to {OUTPUT_DIR}")
