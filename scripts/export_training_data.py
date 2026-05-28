"""
Export training data from conversations.jsonl + support_warehouse.db
into QLoRA-compatible format for fine-tuning Llama 3.1 8B.
"""
import json
import sqlite3
from pathlib import Path

def load_conversations(path: str) -> list[dict]:
    entries = []
    if not Path(path).exists():
        print(f"File not found: {path}")
        return entries
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries

def export_instruction_pairs(entries: list[dict]) -> list[dict]:
    pairs = []
    for entry in entries:
        messages = entry.get("messages", [])
        for i in range(0, len(messages) - 1, 2):
            if i + 1 < len(messages):
                user_msg = messages[i].get("content", "")
                asst_msg = messages[i + 1].get("content", "")
                if user_msg and asst_msg:
                    pairs.append({
                        "instruction": user_msg,
                        "output": asst_msg,
                        "source": entry.get("source", "unknown"),
                        "domain": entry.get("domain", ""),
                        "timestamp": entry.get("timestamp", "")
                    })
    return pairs

def export_warehouse_qa(db_path: str) -> list[dict]:
    pairs = []
    if not Path(db_path).exists():
        print(f"DB not found: {db_path}")
        return pairs
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT question, answer, category FROM qa_log WHERE question != '' AND answer != ''"
    ).fetchall()
    conn.close()
    for row in rows:
        pairs.append({
            "instruction": row[0],
            "output": row[1],
            "source": "warehouse_qa",
            "category": row[2]
        })
    return pairs

def export_warehouse_canned(db_path: str) -> list[dict]:
    pairs = []
    if not Path(db_path).exists():
        return pairs
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT title, response_body FROM canned_responses WHERE response_body != ''"
    ).fetchall()
    conn.close()
    for row in rows:
        pairs.append({
            "instruction": f"Generate canned response for: {row[0]}",
            "output": row[1],
            "source": "canned_response",
            "category": row[0]
        })
    return pairs

def export_warehouse_issues(db_path: str) -> list[dict]:
    pairs = []
    if not Path(db_path).exists():
        return pairs
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT domain, issue_type, description, status, resolution "
        "FROM issues WHERE description != ''"
    ).fetchall()
    conn.close()
    for row in rows:
        desc = row[2] or ""
        resolution = row[4] or ""
        pairs.append({
            "instruction": f"Domain: {row[0]}\nIssue type: {row[1]}\nDescription: {desc}",
            "output": f"Status: {row[3]}\nResolution: {resolution}",
            "source": "warehouse_issue",
            "domain": row[0]
        })
    return pairs

def save_jsonl(pairs: list[dict], output_path: str):
    with open(output_path, "w") as f:
        for p in pairs:
            entry = {
                "instruction": p["instruction"],
                "input": "",
                "output": p["output"],
                "source": p.get("source", ""),
                "domain": p.get("domain", ""),
                "category": p.get("category", "")
            }
            f.write(json.dumps(entry) + "\n")

def main(conversations_path: str, warehouse_path: str, output_dir: str):
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    print("Loading conversations...")
    entries = load_conversations(conversations_path)
    conv_pairs = export_instruction_pairs(entries)
    print(f"  {len(conv_pairs)} instruction pairs from conversations")

    print("Loading warehouse QA...")
    qa_pairs = export_warehouse_qa(warehouse_path)
    print(f"  {len(qa_pairs)} QA pairs from warehouse")

    print("Loading canned responses...")
    canned_pairs = export_warehouse_canned(warehouse_path)
    print(f"  {len(canned_pairs)} canned response pairs")

    print("Loading issue records...")
    issue_pairs = export_warehouse_issues(warehouse_path)
    print(f"  {len(issue_pairs)} issue pairs")

    all_pairs = conv_pairs + qa_pairs + canned_pairs + issue_pairs
    print(f"\nTotal: {len(all_pairs)} training pairs")

    import random
    random.shuffle(all_pairs)

    split = int(len(all_pairs) * 0.9)
    train = all_pairs[:split]
    val = all_pairs[split:]

    save_jsonl(train, f"{output_dir}/train.jsonl")
    save_jsonl(val, f"{output_dir}/val.jsonl")

    print(f"\nSaved to {output_dir}/")
    print(f"  train.jsonl: {len(train)} examples")
    print(f"  val.jsonl: {len(val)} examples")

    print("\nUpload to Google Colab for QLoRA fine-tuning:")
    print(f"  tar -czf training_data.tar.gz -C {output_dir} .")
    print("  # Then upload training_data.tar.gz to Colab")

if __name__ == "__main__":
    import sys
    conv_path = sys.argv[1] if len(sys.argv) > 1 else "/root/conversations.jsonl"
    db_path = sys.argv[2] if len(sys.argv) > 2 else "/root/support_warehouse.db"
    out_dir = sys.argv[3] if len(sys.argv) > 3 else "/root/ai-support/training_data"
    main(conv_path, db_path, out_dir)
