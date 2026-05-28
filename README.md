# 1-grid AI Support Agent

Self-hosted AI agent for L1 support ticket handling at 1-grid South Africa.

## Project Structure
```
ai-support/
├── app/
│   ├── main.py           # FastAPI server with all endpoints
│   ├── config.py         # Settings via env vars
│   ├── agent/
│   │   ├── ollama_client.py  # Ollama API integration
│   │   └── pipeline.py       # Full diagnosis pipeline
│   ├── rag/
│   │   ├── chroma_client.py  # ChromaDB vector store
│   │   ├── kb_ingest.py      # KB article ingestion
│   │   └── retriever.py      # RAG context retrieval
│   ├── warehouse/
│   │   └── queries.py        # Support warehouse DB access
│   └── zonewalk/
│       └── runner.py         # Zonewalk DNS diagnostic tool
├── scripts/
│   ├── export_training_data.py   # Export datasets for fine-tuning
│   ├── colab_train.py            # QLoRA fine-tuning notebook
│   ├── deploy.sh                 # One-shot VPS deployment
│   └── Modelfile                 # Ollama model config
├── requirements.txt
└── .env.example
```

## Quick Start (VPS)
```bash
# Deploy everything
sudo bash scripts/deploy.sh

# Or step by step:
ollama pull llama3.1:8b
source venv/bin/activate
pip install -r requirements.txt
python -m app.rag.kb_ingest    # Ingest KB articles into ChromaDB
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API Endpoints
| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/ticket` | POST | Full ticket processing pipeline |
| `/diagnose` | POST | Quick domain diagnosis |
| `/kb/query` | POST | Search KB articles |
| `/kb/ingest` | POST | Ingest KB + warehouse QA |
| `/warehouse/search` | POST | Search warehouse DB |
| `/zonewalk` | POST | Run zonewalk on domain |
| `/n8n/webhook` | POST | n8n Freshdesk webhook receiver |

## Pipeline Flow
1. Freshdesk webhook -> `/n8n/webhook`
2. Zonewalk runs on domain
3. ChromaDB searches KB for context
4. Warehouse DB checked for history
5. Llama 3.1 8B returns diagnosis + draft
6. High confidence -> auto-send flag
7. Low confidence -> flagged for review
8. Every exchange logged to conversations.jsonl

## Fine-tuning
```bash
# Export training data
python scripts/export_training_data.py

# Upload to Google Colab, run colab_train.py
# Convert to GGUF, upload to VPS
ollama create 1grid-support -f scripts/Modelfile
```
