#!/bin/bash
# Deploy 1-grid AI Support Agent to VPS
# Run this on the VPS after rsync/scp from dev machine

set -e

echo "=== 1-grid AI Support Agent Deployment ==="

# 1. Variables
PROJECT_DIR="${1:-/root/ai-support}"
MODEL="${2:-llama3.1:8b}"

# 2. Install system deps
echo "[1/6] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq curl python3-pip sqlite3 2>/dev/null || yum install -y -q curl python3-pip sqlite 2>/dev/null

# 3. Install Ollama if not present
echo "[2/6] Installing Ollama..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi

# 4. Pull model
echo "[3/6] Pulling model: $MODEL..."
ollama pull "$MODEL"

# 5. Setup Python venv (fallback if not exists)
echo "[4/6] Setting up Python environment..."
if [ ! -d "$PROJECT_DIR/venv" ]; then
    python3 -m venv "$PROJECT_DIR/venv"
fi
source "$PROJECT_DIR/venv/bin/activate"
pip install -q -r "$PROJECT_DIR/requirements.txt"

# 6. Ingest KB articles into ChromaDB
echo "[5/6] Ingesting KB articles..."
cd "$PROJECT_DIR"
python -m app.rag.kb_ingest

# 7. Start service
echo "[6/6] Starting FastAPI service..."
cat > /etc/systemd/system/ai-support.service << 'EOF'
[Unit]
Description=1-grid AI Support Agent
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/ai-support
Environment=OLLAMA_URL=http://localhost:11434
Environment=OLLAMA_MODEL=llama3.1:8b
Environment=WAREHOUSE_DB=/root/support_warehouse.db
Environment=CONVERSATIONS_JSONL=/root/conversations.jsonl
Environment=CHROMA_DB_PATH=/root/ai-support/data/chroma
ExecStart=/root/ai-support/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ai-support.service

echo ""
echo "=== Deployment Complete ==="
echo "API running at: http://localhost:8000"
echo "Health check:   curl http://localhost:8000/health"
echo "Logs:          journalctl -u ai-support -f"
