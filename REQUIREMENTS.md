# 1-grid AI Support Agent — Full Requirements

## 1. HARDWARE REQUIREMENTS

### Development Machine (Coding Only)
| Component | Minimum | Recommended |
|---|---|---|
| CPU | Intel Core i5 | Intel Core i5+ |
| RAM | 8 GB | 16 GB |
| OS | Windows 11 | Windows 11 / WSL2 |
| Disk | 10 GB free | 20 GB free (SSD) |
| Tools | VS Code, Python 3.11 | VS Code + WSL2 |

### Training (Google Colab)
| Component | Free Tier | Colab Pro |
|---|---|---|
| GPU | T4 (16 GB VRAM) | A100 (40 GB VRAM) |
| RAM | ~12 GB | ~25 GB |
| Disk | ~80 GB | ~150 GB |
| Time (QLoRA 8B) | ~3-4 hours | ~1-2 hours |
| Cost | Free | ~R180/month |

### Production VPS (Hetzner/Contabo ~R200-300/month)
| Component | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB SSD | 40 GB SSD |
| OS | Ubuntu 22.04 / Debian 12 | Ubuntu 24.04 |
| Bandwidth | 1 TB/month | 2 TB/month |
| Python | 3.10+ | 3.11 |

### VPS Storage Breakdown
| Item | Size |
|---|---|
| Ollama binary + models | ~5-6 GB (Llama 3.1 8B = ~4.5 GB) |
| ChromaDB vectors | ~50-200 MB (grows with KB) |
| Python venv + packages | ~1 GB |
| Warehouse DB + logs | ~10-100 MB |
| Code + scripts | ~1 MB |
| **Total** | **~6-8 GB** |

---

## 2. SYSTEM SOFTWARE

### VPS OS Packages
| Package | Purpose | Install |
|---|---|---|
| `curl` | Download scripts/models | `apt install curl` |
| `python3`, `python3-pip` | Python runtime | `apt install python3 python3-pip` |
| `python3-venv` | Virtual environment | `apt install python3-venv` |
| `sqlite3` | Warehouse DB access | `apt install sqlite3` |
| `dnsutils` (dig, nslookup) | DNS diagnostics | `apt install dnsutils` |
| `whois` | Domain WHOIS lookups | `apt install whois` |
| `systemd` | Service management | Pre-installed on Ubuntu/Debian |

### Ollama (Model Runtime)
| Item | Value |
|---|---|
| Binary install | `curl -fsSL https://ollama.com/install.sh | sh` |
| Service port | 11434 (localhost only) |
| Service name | `ollama.service` |
| Default model | `llama3.1:8b` (~4.5 GB) |
| Fine-tuned model | `1grid-support` (custom GGUF) |

### Python Packages (from requirements.txt)
| Package | Version | Purpose |
|---|---|---|
| `fastapi` | >=0.110.0 | REST API framework |
| `uvicorn[standard]` | >=0.29.0 | ASGI server |
| `httpx` | >=0.27.0 | Async HTTP client (Ollama API) |
| `chromadb` | >=1.5.0 | Vector store (RAG) |
| `pydantic-settings` | >=2.0.0 | Environment config |
| `python-multipart` | >=0.0.9 | Form data parsing |
| `aiofiles` | >=24.0.0 | Async file I/O |

### Pre-installed Packages (VPS already has these)
These are already in `/root/ai-support-env/`:
| Package | Version | Purpose |
|---|---|---|
| chromadb | 1.5.9 | Vector store |
| fastapi | 0.136.3 | API framework |
| uvicorn | 0.48.0 | Server |
| langchain | 1.3.2 | LLM framework (potential future use) |
| langchain_core | 1.4.0 | LangChain core |
| openai | 2.38.0 | OpenAI-compatible client |
| huggingface_hub | 1.16.4 | Model hub |
| sqlalchemy | 2.0.50 | SQL ORM |
| httpx | 0.28.1 | HTTP client |
| pydantic | 2.13.4 | Validation |
| aiohttp | 3.13.5 | Async HTTP |
| numpy | 2.4.6 | Numerical computing |
| onnxruntime | 1.26.0 | ML inference |

---

## 3. DATA REQUIREMENTS

### 3a. Source Data Files
| File | Path | Format | Size | Purpose |
|---|---|---|---|---|
| Support Warehouse DB | `/root/support_warehouse.db` | SQLite | ~140 KB | Issues, servers, clients, QA, canned responses, SOPs |
| Conversations log | `/root/conversations.jsonl` | JSONL | ~8-60 KB | All AI exchanges for training |
| Session context | `/root/robert_session_context.md` | Markdown | ~28 KB | Infrastructure details, commands, incidents |
| Session dump | `/root/robert_session_dump.md` | Markdown | ~56 KB | Full session history |
| Robert Conv DB | `/root/robert_conv.db` | SQLite | ~28 KB | Conversation database |
| Response drafts | `/root/response_drafts/*.md` | Markdown | ~1.4 KB each | Drafted ticket responses |
| Zonewalk binary | `/usr/bin/zonewalk` | Binary | ~43 KB | DNS diagnostic tool |

### 3b. Warehouse DB Schema (10 tables)
| Table | Records | Purpose |
|---|---|---|
| `issues` | ~14 | Issue tracking per domain |
| `freshdesk_logs` | ~35 | All Freshdesk activity logs |
| `servers` | ~21 | Server inventory (hostname, IP, OS, issues) |
| `clients` | ~8 | Known clients and domains |
| `issue_patterns` | ~4 | Recurring issue patterns |
| `quick_ref` | ~26 | Reference data (delisting URLs, nameservers, etc.) |
| `canned_responses` | ~4 | Response templates |
| `qa_log` | ~17 | Q&A history |
| `product_plans` | ~10 | VPS/managed/dedicated plans |
| `sop` | ~1 | Standard Operating Procedures |

### 3c. KB Articles (17 built-in)
| Category | Articles |
|---|---|
| Email | 6 (settings, troubleshooting, SMTP 451/550, SPF, mail flow, MC timeout) |
| DNS | 2 (nameservers, DMARC) |
| Security | 4 (ModSecurity, CS Firewall, BitNinja, spammer alert) |
| Domains | 2 (ServerHold, OpenProvider) |
| Hosting | 1 (VPS packages) |
| Backup | 1 (Acronis restart) |
| Other | 1 (Plesk email password) |

### 3d. Training Data (for fine-tuning)
| Source | Expected Pairs | Format |
|---|---|---|
| conversations.jsonl | ~10-50 | Instruction-output pairs |
| Warehouse QA log | ~17 | Question-answer pairs |
| Canned responses | ~4 | Title-response pairs |
| Issue records | ~14 | Domain-issue-resolution triples |
| **Total training** | **~45-85** | JSONL for QLoRA |

---

## 4. EXTERNAL INTEGRATIONS

### Freshdesk (Ticket System)
| Requirement | Details |
|---|---|
| Webhook target | `POST http://VPS_IP:8000/n8n/webhook` |
| Webhook payload | Domain, issue description, ticket ID, customer email |
| API key | For ticket status updates (optional) |

### n8n (Workflow Orchestration)
| Requirement | Details |
|---|---|
| Trigger | Freshdesk webhook (new ticket) |
| Actions | Extract domain + issue, call AI API, decide auto-send vs flag |
| Auto-send | POST response back to Freshdesk (high confidence) |
| Flag review | Create Freshdesk internal note with diagnosis (low confidence) |

### Teleport (SSH Access)
| Requirement | Details |
|---|---|
| Purpose | Run zonewalk on customer servers |
| Integration | Script-based via subprocess calls |
| Auth | Teleport proxy at teleport.hostserv.co.za:3025 |

---

## 5. NETWORK REQUIREMENTS

### VPS Firewall (Ports)
| Port | Service | Source |
|---|---|---|
| 22 | SSH | Admin IPs only |
| 8000 | FastAPI (AI Agent) | n8n server, dev machine |
| 11434 | Ollama API | localhost only (127.0.0.1) |
| 80/443 | Portfolio/website | Public (optional) |

### API Security
- Ollama bound to localhost (not exposed externally)
- FastAPI can be behind nginx reverse proxy with auth
- No API keys currently required (add via middleware if exposed publicly)

---

## 6. MONITORING

| Tool | Purpose | Status |
|---|---|---|
| Grafana | Dashboard (request volume, latency, confidence scores) | Planned |
| Prometheus | Metrics collection | Planned |
| Telegram alerts | Notification on low-confidence tickets | Planned |
| systemd journal | Service logs | Built-in |
| uvicorn logs | Request logging | Built-in |

---

## 7. DEPLOYMENT CHECKLIST

### Initial Setup
- [ ] VPS provisioned (Ubuntu 24.04, 4 GB RAM, 40 GB disk)
- [ ] SSH access configured (key-based)
- [ ] DNS records for API domain (optional)
- [ ] Firewall ports opened (22, 8000)

### Software Install
- [ ] System packages: curl, python3, python3-pip, python3-venv, sqlite3, dnsutils, whois
- [ ] Ollama installed and running
- [ ] Llama 3.1 8B pulled (`ollama pull llama3.1:8b`)
- [ ] Python venv created and requirements installed
- [ ] ChromaDB KB ingested (`python -m app.rag.kb_ingest`)

### Runtime
- [ ] FastAPI service running (systemd)
- [ ] Health check passes (`curl localhost:8000/health`)
- [ ] Zonewalk works from API
- [ ] Warehouse DB queries work
- [ ] Ollama responds to chat requests

### Integration
- [ ] n8n workflow created (Freshdesk webhook -> AI API)
- [ ] Freshdesk webhook configured
- [ ] Training data export tested
- [ ] Teleport zonewalk execution tested

### Operations
- [ ] Logging to conversations.jsonl confirmed
- [ ] Confidence threshold tuned (default: 0.85)
- [ ] Manual review workflow defined
- [ ] Monthly retraining schedule set

---

## 8. COST BREAKDOWN

| Item | Monthly | Setup |
|---|---|---|
| VPS (Hetzner/Contabo) | R200-300 | R0 |
| Google Colab Pro | R180 | R0 |
| Domain (+ SSL) | R0 (existing) | R0 |
| Ollama (open source) | R0 | R0 |
| ChromaDB (open source) | R0 | R0 |
| n8n (self-hosted) | R0 | R0 |
| **Total** | **R380-480/month** | **R0** |

---

## 9. PHASE REQUIREMENTS BY PHASE

### Phase 1 — Data Collection (Month 1)
**Requirements:**
- conversations.jsonl logging active (done)
- Warehouse DB populated (done — 10 tables)
- KB articles documented (done — 17 articles + URLs)
- Training data export script ready (done — `scripts/export_training_data.py`)
- Data normalization pipeline running (done — `scripts/export_training_data.py`)

### Phase 2 — Fine-tune + Pipeline (Month 2)
**Requirements:**
- Colab fine-tuning notebook ready (done — `scripts/colab_train.py`)
- QLoRA adapter trained on ~50+ conversation pairs
- GGUF conversion completed
- Ollama Modelfile created (done — `scripts/Modelfile`)
- Basic n8n pipeline: Freshdesk -> API -> response

### Phase 3 — Shadow Mode (Month 3)
**Requirements:**
- Agent runs silently alongside human agent
- All diagnoses logged but not sent
- Compare agent diagnosis vs human resolution
- Confidence calibration based on comparison data

### Phase 4-6 — Graduated Autonomy
- Confidence thresholds tuned per issue type
- High-confidence email/DNS issues auto-sent
- Complex/server issues always flagged
- Monthly retraining with new conversation data

---

## 10. FILES DELIVERED

| File | Lines | Purpose |
|---|---|---|
| `app/main.py` | 138 | FastAPI server (13 endpoints) |
| `app/config.py` | 11 | Environment settings |
| `app/agent/ollama_client.py` | 87 | Ollama API + system prompt |
| `app/agent/pipeline.py` | 117 | Full diagnosis pipeline |
| `app/rag/chroma_client.py` | 35 | ChromaDB vector store |
| `app/rag/kb_ingest.py` | 174 | 17 KB articles + warehous ingestion |
| `app/rag/retriever.py` | 22 | RAG context retrieval |
| `app/warehouse/queries.py` | 100 | Full warehouse DB interface |
| `app/zonewalk/runner.py` | 47 | Zonewalk subprocess runner |
| `scripts/deploy.sh` | 73 | One-shot VPS deployment |
| `scripts/export_training_data.py` | 113 | Training data export |
| `scripts/colab_train.py` | 113 | QLoRA Colab notebook |
| `scripts/Modelfile` | 16 | Ollama model config |
| `.env.example` | 11 | Environment template |
| `requirements.txt` | 7 | Python dependencies |
