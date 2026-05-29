import json
import logging
import re
import socket
import asyncio
import random
import httpx
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Body, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from app.config import settings
from app.agent.pipeline import SupportPipeline
from app.rag.chroma_client import ChromaService
from app.rag.kb_ingest import ingest_all_kb, ingest_from_warehouse
from app.rag.retriever import retrieve_context_structured
from app.warehouse.mongo_warehouse import MongoWarehouse
from app.zonewalk.runner import run_zonewalk, run_dig, run_whois
from app.zonewalk.runner import (
    run_zonewalk_full, parse_email_headers, check_propagation,
    whois_lookup, port_scan, check_blocklists, enum_subdomains,
    http_check, Resolver, GRID_NS_PATTERNS, COMPETITORS, COMMON_PORTS,
    COMMON_SUBDOMAINS, BLACKLISTS
)

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)

pipeline = SupportPipeline()

def _llm():
    return pipeline.groq if pipeline.use_groq else pipeline.ollama

def _llm_name():
    return settings.groq_model if pipeline.use_groq else settings.ollama_model

# ── Chat Session Manager ──
import uuid
from datetime import datetime, timedelta

class ChatSession:
    __slots__ = ("messages", "created_at", "last_active")
    def __init__(self):
        self.messages: list[dict] = []
        self.created_at = datetime.utcnow()
        self.last_active = datetime.utcnow()

class SessionManager:
    def __init__(self, max_age_minutes: int = 120, max_messages: int = 50):
        self.sessions: dict[str, ChatSession] = {}
        self.max_age = timedelta(minutes=max_age_minutes)
        self.max_messages = max_messages

    def get_or_create(self, session_id: str) -> ChatSession:
        if session_id not in self.sessions:
            self.sessions[session_id] = ChatSession()
        self.sessions[session_id].last_active = datetime.utcnow()
        return self.sessions[session_id]

    def add_message(self, session_id: str, role: str, content: str):
        session = self.get_or_create(session_id)
        session.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        if len(session.messages) > self.max_messages:
            session.messages = session.messages[-self.max_messages:]

    def get_history(self, session_id: str, limit: int = 20) -> list[dict]:
        session = self.get_or_create(session_id)
        return session.messages[-limit:]

sessions = SessionManager()

chroma = ChromaService()
warehouse = MongoWarehouse()

templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
BASE_PATH = Path(__file__).resolve().parent.parent

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting 1-grid AI Support Agent (model: {_llm_name()})")
    try:
        from app.rag.kb_ingest import ingest_all_kb
        ing = ingest_all_kb()
        logger.info(f"KB auto-ingest: {ing['ingested']} new, {ing['total']} total")
    except Exception as e:
        logger.warning(f"KB auto-ingest skipped: {e}")

    try:
        if not warehouse.db or not warehouse.db.list_collection_names():
            logger.info("MongoDB appears empty, importing from SQLite")
            counts = warehouse.import_from_sqlite(settings.warehouse_db)
            conv_count = warehouse.import_conversations(settings.conversations_jsonl)
            logger.info(f"MongoDB warehouse loaded: {sum(counts.values())} docs from SQLite, {conv_count} conversations")
        else:
            logger.info(f"Warehouse counts: {warehouse.counts()}")
    except Exception as e:
        logger.warning(f"MongoDB warehouse import skipped: {e}")

    yield
    logger.info("Shutting down")

app = FastAPI(
    title="1-grid AI Support Agent",
    description="Self-hosted AI agent for L1 support ticket handling",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

J2 = "jinja2"

def esc(s):
    if s is None: return ""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def esc_js(s):
    """Escape string for embedding in a single-quoted JS context."""
    if s is None: return ""
    return str(s).replace("\\","\\\\").replace("'","\\'").replace("\n","\\n").replace("\r","\\r")

# --- Request Models ---

class TicketRequest(BaseModel):
    domain: str
    issue: str
    ticket_id: str = None
    customer_email: str = None

class DiagnoseRequest(BaseModel):
    domain: str
    issue: str = ""

class KBQueryRequest(BaseModel):
    query: str
    n_results: int = 5

class WarehouseQueryRequest(BaseModel):
    query: str

class ChatRequest(BaseModel):
    message: str

class ZonewalkCheckRequest(BaseModel):
    domain: str
    deep: bool = False
    ports: bool = False
    reputation: bool = False

class HeadersRequest(BaseModel):
    headers: str

class LogRequest(BaseModel):
    content: str

# --- JSON API Endpoints (unchanged) ---

@app.get("/health")
async def health():
    return {"status": "ok", "model": _llm_name()}

@app.get("/health/ollama")
async def health_ollama():
    try:
        import httpx
        r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3)
        if r.status_code == 200:
            return {"status": "ok", "model": _llm_name()}

    except:
        return {"status": "disconnected", "model": None}


@app.post("/zonewalk/check")
async def zonewalk_check(req: ZonewalkCheckRequest):
    result = run_zonewalk_full(req.domain, deep=req.deep, ports=req.ports, reputation=req.reputation)
    return result.to_dict()

@app.post("/mail/headers")
async def mail_headers_analyze(req: HeadersRequest):
    return parse_email_headers(req.headers)

@app.post("/propagation")
async def propagation_check(domain: str = Body(...)):
    res = Resolver()
    a_records = res.a(domain)
    if a_records:
        return {"domain": domain, "propagation": check_propagation(domain, a_records), "a_records": a_records}
    return {"domain": domain, "propagation": [], "a_records": []}

@app.post("/nameservers")
async def nameservers_check(domain: str = Body(...)):
    res = Resolver()
    ns = res.ns(domain)
    provider = "Unknown"; is_grid = False; hosting_type = ""
    for ns_host in ns:
        for pattern, htype in GRID_NS_PATTERNS.items():
            if pattern in ns_host.lower():
                provider = "1-grid"; is_grid = True; hosting_type = htype; break
        if is_grid: break
    if not is_grid:
        for pattern, name in COMPETITORS:
            if any(pattern in n.lower() for n in ns):
                provider = name; break
    return {"domain": domain, "nameservers": ns, "is_grid": is_grid, "provider": provider, "hosting_type": hosting_type}

@app.post("/log/analyze")
async def log_analyze(req: LogRequest):
    text = req.content
    findings = []
    lines = text.split("\n")[:200]
    phperrs = [l for l in lines if re.search(r"PHP\s+(Fatal|Warning|Notice|Parse|Error)", l, re.I)]
    if phperrs: findings.append({"type": "PHP_Errors", "count": len(phperrs), "samples": phperrs[:5]})
    mysqlerrs = [l for l in lines if re.search(r"(MySQL|MariaDB|mysqli|PDOException|SQLSTATE)", l, re.I)]
    if mysqlerrs: findings.append({"type": "MySQL_Errors", "count": len(mysqlerrs), "samples": mysqlerrs[:5]})
    http4xx = [l for l in lines if re.search(r"\s(401|403|404)\s", l)]
    if http4xx: findings.append({"type": "HTTP_4xx", "count": len(http4xx), "samples": http4xx[:3]})
    http5xx = [l for l in lines if re.search(r"\s(500|502|503|504)\s", l)]
    if http5xx: findings.append({"type": "HTTP_5xx", "count": len(http5xx), "samples": http5xx[:3]})
    wperrs = [l for l in lines if re.search(r"(WordPress|wp_|WPDB|wp_error)", l, re.I)]
    if wperrs: findings.append({"type": "WordPress", "count": len(wperrs), "samples": wperrs[:5]})
    toerrs = [l for l in lines if re.search(r"(timeout|timed\s*out|connection\s+refused)", l, re.I)]
    if toerrs: findings.append({"type": "Connection_Timeout", "count": len(toerrs), "samples": toerrs[:3]})
    reserrs = [l for l in lines if re.search(r"(disk\s+full|out\s+of\s+memory|memory\s+exhausted|disk\s+quota)", l, re.I)]
    if reserrs: findings.append({"type": "Resource_Limit", "count": len(reserrs), "samples": reserrs[:3]})
    permerrs = [l for l in lines if re.search(r"(permission\s+denied|cannot\s+open|failed\s+to\s+open)", l, re.I)]
    if permerrs: findings.append({"type": "Permission_Denied", "count": len(permerrs), "samples": permerrs[:3]})
    return {"total_lines": len(text.split("\n")), "findings": findings}

@app.post("/tools/dig")
async def tools_dig(domain: str = Body(...), query_type: str = Body("ANY")):
    return run_dig(domain, query_type)

@app.post("/tools/whois")
async def tools_whois(domain: str = Body(...)):
    data = whois_lookup(domain)
    return {"domain": domain, "registrar": data.get("registrar",""), "expiry": data.get("expiry",""), "status": data.get("status",""), "raw": data.get("raw","")[:500]}

@app.post("/tools/portscan")
async def tools_portscan(domain: str = Body(...)):
    open_ports = port_scan(domain)
    return {"domain": domain, "open_ports": [{"port": p, "service": n} for p, n in open_ports]}

@app.post("/tools/subdomains")
async def tools_subdomains(domain: str = Body(...)):
    subs = enum_subdomains(domain)
    return {"domain": domain, "subdomains": subs}

@app.get("/tools/blocklists")
async def tools_blocklists(ip: str):
    return {"ip": ip, "blocklists": check_blocklists(ip)}

@app.post("/tools/httpcheck")
async def tools_httpcheck(domain: str = Body(...)):
    http_s, https_s, ssl_d = http_check(domain)
    return {"domain": domain, "http": http_s, "https": https_s, "ssl_days": ssl_d}

@app.post("/ticket")
async def process_ticket(req: TicketRequest):
    result = await pipeline.process_ticket(
        domain=req.domain, issue=req.issue,
        ticket_id=req.ticket_id, customer_email=req.customer_email
    )
    return result

@app.post("/diagnose")
async def diagnose(req: DiagnoseRequest):
    result = await pipeline.quick_diagnose(domain=req.domain, issue=req.issue)
    return result

@app.post("/kb/query")
async def query_kb(req: KBQueryRequest):
    results = retrieve_context_structured(req.query, req.n_results)
    return {"query": req.query, "results": results}

@app.post("/kb/ingest")
async def ingest_kb():
    result = ingest_all_kb()
    db_result = ingest_from_warehouse(settings.warehouse_db)
    return {**result, **db_result}

@app.post("/warehouse/search")
async def warehouse_search(req: WarehouseQueryRequest):
    return warehouse.search_all(req.query)

@app.get("/warehouse/server")
async def warehouse_server(hostname: str = None, ip: str = None):
    return {"servers": warehouse.get_server(hostname=hostname, ip=ip)}

@app.get("/servers")
async def list_servers():
    return {"servers": warehouse.get_server()}

@app.get("/warehouse/canned")
async def canned_response(title: str):
    return {"responses": warehouse.get_canned_response(title)}

@app.get("/warehouse/quickref")
async def quickref(category: str = None):
    return {"references": warehouse.get_quick_ref(category)}

@app.get("/warehouse/sop")
async def sop(title: str = None):
    return {"sops": warehouse.get_sop(title)}

@app.get("/warehouse/patterns")
async def patterns(name: str = None):
    return {"patterns": warehouse.get_issue_patterns(name)}

@app.post("/zonewalk")
async def zonewalk(req: DiagnoseRequest):
    return run_zonewalk(req.domain)

@app.post("/dig")
async def dig(domain: str, query_type: str = "ANY"):
    return run_dig(domain, query_type)

@app.post("/whois")
async def whois(domain: str):
    return run_whois(domain)

@app.get("/conversations")
async def conversations(limit: int = 50):
    convs = warehouse.get_conversations(limit)
    return {"conversations": convs, "total": len(warehouse.conversations.all())}

@app.get("/warehouse/counts")
async def warehouse_counts():
    return warehouse.counts()

@app.get("/issues")
async def issues(q: str = "", limit: int = 20):
    return {"issues": warehouse.search_issues(q, limit)}

@app.get("/servers/enriched")
async def servers_enriched():
    return {"servers": warehouse.servers_enriched(), "total": len(warehouse.servers_enriched())}

@app.get("/tickets")
async def tickets(q: str = "", limit: int = 20):
    return {"tickets": warehouse.search_tickets(q, limit)}

@app.get("/tickets/by-server")
async def tickets_by_server():
    return {"servers": warehouse.tickets_by_server()}

@app.get("/kb/search")
async def kb_search(q: str = "", n: int = 10):
    if not q:
        return {"articles": []}
    results = warehouse.search_kb(q, n)
    articles = []
    for r in results:
        articles.append({
            "title": r.get("title", ""),
            "category": r.get("category", ""),
            "content": (r.get("content", "") or "")[:2000],
        })
    return {"articles": articles}

@app.get("/kb/detail")
async def kb_detail(title: str = ""):
    if not title:
        return {"error": "title required"}
    article = warehouse.get_kb_article(title)
    if article:
        return {"article": {"title": article.get("title", ""), "category": article.get("category", ""), "content": article.get("content", "")}}
    return {"error": "not found"}

@app.get("/quickref/by-category")
async def quickref_by_category():
    refs = warehouse.get_quick_ref()
    groups = {}
    for r in refs:
        cat = r.get("category", "General")
        groups.setdefault(cat, []).append(r)
    return {"categories": groups}

@app.get("/")
async def index():
    return FileResponse(str(BASE_PATH / "static" / "index.html"))

@app.post("/chat")
async def chat(msg: str = Body(..., embed=True)):
    return await _handle_chat(msg)

async def _handle_chat(msg: str):
    msg = msg.strip()
    if not msg:
        return {"response": "Please enter a message."}

    if msg == "/help":
        return {"response": ("Commands:\n  <domain.tld> <issue>     Diagnose\n  /history <domain>        Lookup domain\n  /kb <query>              Search KB\n  /canned <topic>          Canned responses\n  /quickref <query>        Quick ref\n  /servers                 List servers\n  /client <query>          Client info\n  /status                  System status\n  /help                    This message")}

    if msg == "/status":
        ollama_ok = False
        try:
            import httpx
            r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3)
            ollama_ok = r.status_code == 200
        except: pass
        try:
            wc = warehouse.counts()
            db_info = f"MongoDB: {wc['tickets']} tickets, {wc['issues']} issues"
        except:
            db_info = "MongoDB: check connection"
        return {"response": f"Ollama: {'connected' if ollama_ok else 'disconnected'}\nModel: {_llm_name()}\nDB: {db_info}"}

    if msg.startswith("/history "):
        domain = msg[9:].strip()
        issues = warehouse.search_issues(domain)
        if issues:
            lines = [f"History for {domain}:"]
            for i in issues:
                lines.append(f"  #{i['id']} [{i['status']}] {i['issue_type']} - {(i.get('issue_summary','') or '')[:200]}")
            return {"response": "\n".join(lines)}
        return {"response": f"No history for {domain}"}

    if msg.startswith("/kb "):
        query = msg[4:].strip()
        hits = warehouse.search_kb(query, 5)
        if hits:
            lines = [f"KB articles for '{query}':"]
            for h in hits:
                lines.append(f"  - {h.get('title','')} ({h.get('category','')})")
            return {"response": "\n".join(lines)}
        return {"response": "No KB articles found."}

    if msg.startswith("/canned "):
        topic = msg[8:].strip()
        resp = warehouse.get_canned_response(topic)
        if resp:
            lines = []
            for r in resp:
                lines.append(f"[{r['title']}]")
                lines.append(f"{(r.get('response_body','') or '')[:300]}...")
            return {"response": "\n".join(lines)}
        return {"response": f"No canned responses for '{topic}'"}

    if msg.startswith("/quickref "):
        query = msg[10:].strip()
        refs = warehouse.get_quick_ref(query)
        if refs:
            lines = [f"Quick refs for '{query}':"]
            for r in refs:
                lines.append(f"  [{r['category']}] {r['key_name']}: {(r.get('value','') or '')[:200]}")
            return {"response": "\n".join(lines)}
        return {"response": f"No quick reference for '{query}'"}

    if msg.startswith("/client "):
        query = msg[8:].strip()
        clients = warehouse.search_client(query)
        if clients:
            lines = [f"Clients for '{query}':"]
            for c in clients:
                dm = c.get('domains_managed') or ''
                lines.append(f"  {c.get('name','')} ({c.get('email','')}) - {dm[:80]}")
            return {"response": "\n".join(lines)}
        return {"response": f"No client found for '{query}'"}

    if msg == "/servers":
        servers = warehouse.get_server()
        if servers:
            lines = ["Known servers:"]
            for s in servers:
                ki = s.get('known_issues') or 'none'
                lines.append(f"  {s['hostname']} ({s['ip']}) - {s.get('hosting_type','')} - {ki[:100]}")
            return {"response": "\n".join(lines)}
        return {"response": "No servers found"}

    parts = msg.split(" ", 1)
    domain = parts[0].strip()
    issue = parts[1].strip() if len(parts) > 1 else "General inquiry"
    
    if not domain or "." not in domain:
        # ── AI Chat for non-domain queries ──
        try:
            ctx = await _warehouse_context(msg)
            resp = await _llm().chat([
                {"role": "system", "content": f"You are Robert Sibanda, a professional support agent at 1-grid South Africa. Use this context if relevant:\n{ctx}"},
                {"role": "user", "content": msg}
            ])
            return {"response": resp}
        except Exception:
            return {"response": "Usage: <domain.tld> <issue description>"}

    lines = []
    lines.append("=== 🧠 AI Diagnosis ===")

    try:
        diag = await pipeline.quick_diagnose(domain, issue)
        raw = diag["diagnosis"]["raw_response"]
        confidence = diag["diagnosis"]["confidence"]
        zw = diag["zonewalk"]
        if not zw["success"]:
            lines.append("⚠ Zonewalk encountered errors — diagnosis may be incomplete")

        lines.append("")
        for paragraph in raw.split("\n\n"):
            stripped = paragraph.strip()
            if stripped.startswith("ROOT_CAUSE:") or stripped.startswith("ROOT_CAUSE:"):
                lines.append(stripped)
            elif stripped.startswith("DRAFT_RESPONSE:") or stripped.startswith("DRAFT_RESPONSE:"):
                lines.append("")
                lines.append(stripped)
            elif stripped.startswith("CONFIDENCE:"):
                pass  # shown below
            elif stripped.startswith("ACTIONS_TAKEN:") or stripped.startswith("ACTIONS_TAKEN:"):
                lines.append("")
                lines.append(stripped)
            elif stripped.startswith("ESCALATION:") or stripped.startswith("ESCALATION:"):
                pass  # shown below
            elif stripped:
                lines.append(stripped)
        lines.append("")
        lines.append(f"━━━ Confidence: {confidence}")
        if diag["diagnosis"]["needs_escalation"]:
            lines.append("⚠ This issue may need L2/L3 escalation")
    except Exception as e:
        logger.exception("LLM diagnosis failed")
        lines.append(f"⚠ AI diagnosis unavailable: {e}")
        lines.append("")
        lines.append("=== Fallback: Manual Diagnosis ===")
        lines.append("Running zonewalk...")
        z = run_zonewalk(domain)
        zw_text = z.get("stdout", "") or z.get("error", "Not available")
        lines.append(zw_text[:500])
        lines.append("=== Checking warehouse history ===")
        issues = warehouse.search_issues(domain)
        if issues:
            for i in issues[:5]:
                lines.append(f"  #{i['id']} [{i['status']}] {i['issue_type']} - {(i.get('issue_summary','') or '')[:200]}")
        else:
            lines.append("  No history found")
        lines.append("=== Searching KB ===")
        kb_hits = warehouse.search_kb(f"{domain} {issue}", 4)
        if kb_hits:
            for h in kb_hits:
                lines.append(f"  - {h.get('title','')}")
        else:
            lines.append("  No relevant articles")

    return {"response": "\n".join(lines)}

@app.post("/n8n/webhook")
async def n8n_webhook(req: TicketRequest):
    result = await pipeline.process_ticket(
        domain=req.domain, issue=req.issue,
        ticket_id=req.ticket_id, customer_email=req.customer_email
    )
    action = "auto_send" if result["auto_send"] else "flag_for_review"
    return {
        "action": action,
        "confidence": result["diagnosis"]["confidence"],
        "diagnosis": result["diagnosis"]["raw_response"],
        "steps": [{"step": s["step"], "status": s["status"]} for s in result["steps"]]
    }


# ════════════════════════════════════════════════════════════════
# HTMX VIEWS — HTML FRAGMENTS
# ════════════════════════════════════════════════════════════════

def _render(name: str):
    path = Path(__file__).resolve().parent / "templates" / "fragments" / f"{name}.html"
    if not path.exists():
        return HTMLResponse(f'<div class="empty">View "{name}" not found</div>')
    return HTMLResponse(path.read_text(encoding="utf-8"))

@app.get("/views/{name}")
async def view_fragment(name: str):
    valid = ["dashboard","chat","history","kb","tickets","zonewalk","headers",
             "logs","dns","whois","conversations","issues","patterns","servers","quickref","status"]
    if name not in valid:
        return HTMLResponse(f'<div class="empty">View "{name}" not found</div>')
    return _render(name)

# ── CHAT ──

@app.post("/chat/send")
async def chat_send(message: str = Form(...)):
    result = await _handle_chat(message)
    text = result.get("response", "")
    # Log usage
    parts = message.split(" ", 1)
    domain = parts[0].strip() if parts and "." in parts[0] else "unknown"
    try:
        warehouse.log_usage("chat", domain, {"msg": message[:200]})
    except Exception:
        pass
    lines = text.split("\n")
    html = '<div class="msg bot">'
    for line in lines:
        t = line.strip()
        if t.startswith("==="):
            html += f'<div class="badge">{esc(t.replace("=","").strip())}</div>'
        elif re.match(r"^(OK|FAIL|WARN|INFO)\s", t) or "FAIL" in t or "WARN" in t:
            cls = "fail" if "FAIL" in t else "warn"
            html += f'<div class="{cls}">{esc(t)}</div>'
        elif t.startswith("  -") or t.startswith("  #") or t.startswith("    "):
            html += f'<div class="mono" style="padding-left:12px">{esc(t)}</div>'
        elif t:
            html += f"<div>{esc(t)}</div>"
        else:
            html += '<div style="height:3px"></div>'
    html += "</div>"
    return HTMLResponse(html)

# ── CHAT STREAM (SSE) ──

def _fmt_zw_html(zw_text: str) -> str:
    lines = zw_text.split("\n")
    html = '<div class="zw-result" style="background:#0f1729;border:1px solid #334155;border-radius:6px;padding:8px 10px;margin:4px 0;font-family:monospace;font-size:11px;line-height:1.5;white-space:pre-wrap;word-break:break-word">'
    for line in lines:
        t = line.strip()
        if not t:
            continue
        if t.startswith(">>"):
            html += f'<div style="color:#93c5fd;font-weight:500;margin-top:4px">{esc(t)}</div>'
        elif t.startswith("FAIL") or "FAIL" in t:
            html += f'<div style="color:#f87171">{esc(t)}</div>'
        elif t.startswith("OK") or "PASS" in t:
            html += f'<div style="color:#4ade80">{esc(t)}</div>'
        elif t.startswith("WARN") or "WARN" in t:
            html += f'<div style="color:#facc15">{esc(t)}</div>'
        elif t.startswith("ZONEWALK"):
            html += f'<div style="color:#94a3b8;font-size:10px">{esc(t)}</div>'
        else:
            html += f'<div style="color:#cbd5e1">{esc(t)}</div>'
    html += '</div>'
    return html

def _ssse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

async def _warehouse_context(query: str) -> str:
    parts = []
    try:
        kb = warehouse.search_kb(query, 4)
        if kb:
            parts.append("=== KB ARTICLES ===")
            for a in kb:
                title = a.get("title","")
                body = (a.get("body","") or a.get("content","") or "")[:600]
                parts.append(f"Article: {title}\n{body}")
    except: pass
    try:
        qr = warehouse.get_quick_ref(query)
        if qr:
            parts.append("=== QUICK REFERENCES ===")
            for r in qr[:4]:
                parts.append(f"[{r.get('category','')}] {r.get('key_name','')}: {str(r.get('value','') or '')[:300]}")
    except: pass
    try:
        canned = warehouse.get_canned_response(query)
        if canned:
            parts.append("=== CANNED RESPONSES ===")
            for c in canned[:3]:
                parts.append(f"[{c.get('title','')}] {(c.get('response_body','') or '')[:400]}")
    except: pass
    try:
        issues = warehouse.search_issues(query, 3)
        if issues:
            parts.append("=== RELATED ISSUES ===")
            for i in issues:
                parts.append(f"#{i.get('id','')} [{i.get('status','')}] {i.get('issue_type','')} - {(i.get('issue_summary','') or '')[:200]}")
    except: pass
    return "\n\n".join(parts) if parts else ""

async def _log_exchange(session_id: str, msg: str, ai_text: str,
                        domain: str = "", actions: list = None,
                        ctx: str = "", zw_text: str = ""):
    try:
        warehouse.log_chat(session_id, msg, ai_text, domain,
                           _llm_name(), actions or [], ctx, zw_text)
        warehouse.log_usage("chat", f"session={session_id[:16]}", {
            "domain": domain, "actions": (actions or [])[:5]
        })
    except Exception as e:
        logger.warning(f"Log failed: {e}")

async def _handle_chat_stream(message: str, session_id: str):
    msg = message.strip()
    if not msg:
        yield _ssse("error", {"text": "Please enter a message."})
        return

    # Add user msg to memory
    sessions.add_message(session_id, "user", msg)
    history = sessions.get_history(session_id, 10)

    yield _ssse("status", {"text": "Processing..."})

    # ── Slash commands ──
    if msg == "/help":
        text = ("Commands:<br>  <b>&lt;domain.tld&gt; &lt;issue&gt;</b> &nbsp; Diagnose<br>"
                "  <b>/history &lt;domain&gt;</b> &nbsp; Lookup domain<br>"
                "  <b>/kb &lt;query&gt;</b> &nbsp; Search KB<br>"
                "  <b>/canned &lt;topic&gt;</b> &nbsp; Canned responses<br>"
                "  <b>/quickref &lt;query&gt;</b> &nbsp; Quick ref<br>"
                "  <b>/servers</b> &nbsp; List servers<br>"
                "  <b>/client &lt;query&gt;</b> &nbsp; Client info<br>"
                "  <b>/status</b> &nbsp; System status<br>"
                "  <b>/help</b> &nbsp; This message")
        sessions.add_message(session_id, "assistant", text)
        yield _ssse("html", {"html": text})
        yield _ssse("done", {})
        return

    if msg == "/status":
        ollama_ok = False
        try:
            r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3)
            ollama_ok = r.status_code == 200
        except: pass
        grok_ok = bool(settings.groq_api_key)
        try:
            wc = warehouse.counts()
            db_info = f"MongoDB: {wc['tickets']} tickets, {wc['issues']} issues"
        except:
            db_info = "MongoDB: check connection"
        provider = "Groq" if grok_ok else "Ollama (local)"
        model = _llm_name()
        text = (f"<b>LLM:</b> {provider}<br>"
                f"<b>Model:</b> {model}<br>"
                f"<b>Ollama:</b> {'✅ connected' if ollama_ok else '❌ disconnected'}<br>"
                f"<b>DB:</b> {db_info}")
        sessions.add_message(session_id, "assistant", text)
        yield _ssse("html", {"html": text})
        yield _ssse("done", {})
        return

    if msg.startswith("/history "):
        domain = msg[9:].strip()
        issues = warehouse.search_issues(domain)
        if issues:
            html_parts = [f"<b>History for {domain}:</b>"]
            for i in issues:
                s = i.get("status","")
                sc = "#4ade80" if s == "resolved" else "#facc15"
                html_parts.append(
                    f'<div style="padding:4px 0;border-bottom:1px solid #1e293b">'
                    f'<span style="color:#94a3b8">#{i["id"]}</span> '
                    f'<span style="color:{sc}">[{esc(s)}]</span> '
                    f'{esc(i.get("issue_type",""))} &mdash; {esc((i.get("issue_summary","") or "")[:200])}'
                    f'</div>')
            text = "".join(html_parts)
        else:
            text = f"No history for {domain}"
        sessions.add_message(session_id, "assistant", text)
        yield _ssse("html", {"html": text})
        yield _ssse("done", {})
        return

    if msg.startswith("/kb "):
        query = msg[4:].strip()
        hits = warehouse.search_kb(query, 5)
        if hits:
            html_parts = [f"<b>KB articles for '{esc(query)}':</b>"]
            for h in hits:
                html_parts.append(f'<div style="padding:4px 0">📄 {esc(h.get("title",""))} '
                    f'<span style="color:#64748b;font-size:11px">({esc(h.get("category",""))})</span></div>')
            text = "".join(html_parts)
        else:
            text = "No KB articles found."
        sessions.add_message(session_id, "assistant", text)
        yield _ssse("html", {"html": text})
        yield _ssse("done", {})
        return

    if msg.startswith("/canned "):
        topic = msg[8:].strip()
        resp = warehouse.get_canned_response(topic)
        if resp:
            html_parts = []
            for r in resp:
                html_parts.append(f'<div style="background:#1e293b;border-radius:6px;padding:8px;margin:4px 0">'
                    f'<div style="font-weight:500;color:#f1f5f9;margin-bottom:4px">{esc(r["title"])}</div>'
                    f'<div style="font-size:12px;color:#cbd5e1;white-space:pre-wrap">{(esc(r.get("response_body","") or "")[:500])}</div>'
                    f'</div>')
            text = "".join(html_parts)
        else:
            text = f"No canned responses for '{topic}'"
        sessions.add_message(session_id, "assistant", text)
        yield _ssse("html", {"html": text})
        yield _ssse("done", {})
        return

    if msg.startswith("/quickref "):
        query = msg[10:].strip()
        refs = warehouse.get_quick_ref(query)
        if refs:
            html_parts = [f"<b>Quick refs for '{esc(query)}':</b>"]
            for r in refs:
                html_parts.append(f'<div style="padding:3px 0">'
                    f'<span style="color:#64748b;font-size:11px">[{esc(r["category"])}]</span> '
                    f'<span style="color:#e2e8f0;font-size:12px">{esc(r["key_name"])}:</span> '
                    f'<span style="color:#94a3b8;font-size:11px">{(esc(str(r.get("value","")) or "")[:300])}</span>'
                    f'</div>')
            text = "".join(html_parts)
        else:
            text = f"No quick reference for '{query}'"
        sessions.add_message(session_id, "assistant", text)
        yield _ssse("html", {"html": text})
        yield _ssse("done", {})
        return

    if msg.startswith("/client "):
        query = msg[8:].strip()
        clients = warehouse.search_client(query)
        if clients:
            html_parts = [f"<b>Clients for '{esc(query)}':</b>"]
            for c in clients:
                dm = c.get('domains_managed') or ''
                html_parts.append(f'<div style="padding:3px 0">👤 {esc(c.get("name",""))} '
                    f'<span style="color:#64748b;font-size:11px">({esc(c.get("email",""))})</span>'
                    f'<br><span style="color:#94a3b8;font-size:11px">{esc(dm[:100])}</span></div>')
            text = "".join(html_parts)
        else:
            text = f"No client found for '{query}'"
        sessions.add_message(session_id, "assistant", text)
        yield _ssse("html", {"html": text})
        yield _ssse("done", {})
        return

    if msg == "/servers":
        servers = warehouse.get_server()
        if servers:
            html_parts = ["<b>Known servers:</b>"]
            for s in servers:
                ki = s.get('known_issues') or 'none'
                status_color = "#4ade80" if s.get('status') == 'active' else "#facc15"
                html_parts.append(f'<div style="display:flex;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid #1e293b">'
                    f'<span style="color:{status_color}">●</span>'
                    f'<span style="font-weight:500">{esc(s["hostname"])}</span>'
                    f'<span style="color:#64748b;font-size:11px">{esc(s.get("ip",""))}</span>'
                    f'<span style="color:#94a3b8;font-size:11px">{esc(s.get("hosting_type",""))}</span>'
                    f'<br><span style="color:#facc15;font-size:10px">⚠ {esc(ki[:100])}</span></div>')
            text = "".join(html_parts)
        else:
            text = "No servers found"
        sessions.add_message(session_id, "assistant", text)
        yield _ssse("html", {"html": text})
        yield _ssse("done", {})
        return

    # ── Detect domain in message ──
    domain_matches = re.findall(r'(?:^|\s)([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:\s|$)', msg, re.IGNORECASE)
    domain = domain_matches[0].lower().strip(".") if domain_matches else ""
    issue = ""
    if domain:
        raw = domain_matches[0]
        issue = msg.replace(raw, "", 1).strip() or "General inquiry"

    if not domain:
        # ── AI-first chat (every message through LLM, no hardcoded responses) ──
        yield _ssse("status", {"text": "🤖 Thinking..."})
        ai_container = (
            '<div id="ai-analysis" style="background:#0f1729;border:1px solid #334155;border-radius:8px;padding:8px 10px;margin:8px 0">'
            '<b style="color:#94a3b8;font-size:10px;text-transform:uppercase;letter-spacing:0.05em">AI Response</b>'
            '<div id="ai-tokens" style="margin-top:4px;font-size:13px;color:#e2e8f0;white-space:pre-wrap;word-break:break-word;min-height:16px"></div>'
            '</div>'
        )
        yield _ssse("html", {"html": ai_container})

        ctx = await _warehouse_context(msg)
        history_text = "\n".join(f"{h['role']}: {h['content'][:200]}" for h in history[:-1])
        now = datetime.utcnow()
        system_prompt = (
            f"You are Robert Sibanda, a professional support agent at 1-grid South Africa.\n"
            f"Current time: {now.strftime('%A, %d %B %Y %H:%M UTC')}.\n\n"
            f"=== CONVERSATION HISTORY ===\n{history_text}\n\n"
            f"=== KNOWLEDGE BASE ===\n{ctx}\n\n"
            "Guidelines:\n"
            "- Answer hosting/domain questions using KB references\n"
            "- If the user mentions a domain issue without a domain, ask for the domain name\n"
            "- Be concise, warm, professional. Sign as 'Robert' when appropriate."
        )

        full_response = ""
        try:
            async for tok in _llm().chat_stream([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": msg}
            ]):
                full_response += tok
                yield _ssse("token", {"text": tok})
            
            # Final formatting
            formatted = f'<div style="margin-top:4px;font-size:13px;color:#e2e8f0;white-space:pre-wrap;word-break:break-word">{esc(full_response)}</div>'
            yield _ssse("replace_last", {"html": formatted})
            sessions.add_message(session_id, "assistant", full_response)
            await _log_exchange(session_id, msg, full_response, "", ["ai_chat"], ctx)
        except Exception as e:
            logger.exception("AI chat failed")
            err_msg = "I'm having trouble connecting to my brain right now. 🧠 Check /status or try again in a moment!"
            yield _ssse("html", {"html": f'<div style="color:#f87171;font-size:13px">{err_msg}</div>'})
            sessions.add_message(session_id, "assistant", err_msg)

        yield _ssse("done", {})
        return

    # ── Domain diagnosis ──
    issue = issue or "General inquiry"

    yield _ssse("status", {"text": f"🔍 Diagnosing <b>{esc(domain)}</b>..."})

    # Run zonewalk, KB, history in background first
    zw_text = ""
    kb_hits = []
    domain_issues = []
    try:
        zw_result = await asyncio.to_thread(run_zonewalk, domain)
        zw_text = zw_result.get("stdout", "") or zw_result.get("error", "No output")
        warehouse.save_zonewalk_result(domain, zw_result)
    except Exception as e:
        zw_text = ""
    try:
        kb_hits = warehouse.search_kb(f"{domain} {issue}", 4)
    except Exception:
        pass
    try:
        domain_issues = warehouse.search_issues(domain)
    except Exception:
        pass

    # ── AI analysis first (streaming) ──
    yield _ssse("status", {"text": "🧠 Running AI analysis..."})
    try:
        kb_ctx_raw = ""
        if kb_hits:
            parts = []
            for a in kb_hits:
                title = a.get("title", "Untitled")
                content = (a.get("content", "") or "")[:800]
                parts.append(f"--- {title} ---\n{content}")
            kb_ctx_raw = "\n\n".join(parts)

        # Gather additional context
        quickrefs_raw = ""
        try:
            refs = warehouse.get_quick_ref()
            if refs:
                lines = []
                for r in refs[:15]:
                    lines.append(f"[{r.get('category','')}] {r.get('key_name','')}: {str(r.get('value',''))[:200]}")
                quickrefs_raw = "\n".join(lines)
        except Exception:
            pass

        past_issues_raw = ""
        if domain_issues:
            lines = []
            for i in domain_issues[:5]:
                lines.append(f"[{i['status']}] {i['issue_type']}: {(i.get('issue_summary','') or '')[:200]}")
                if i.get('resolution'):
                    lines.append(f"  Resolution: {(i['resolution'])[:200]}")
            past_issues_raw = "\n".join(lines)

        past_convs_raw = ""
        try:
            convs = warehouse.search_conversations_by_domain(domain, 5)
            if convs:
                lines = []
                for c in convs[:5]:
                    msg = (c.get("content","") or c.get("message","") or "")[:200]
                    lines.append(f"[{c.get('timestamp','')[:10]}] {msg}")
                past_convs_raw = "\n".join(lines)
        except Exception:
            pass

        prompt = (
            f"Domain: {domain}\n"
            f"Issue reported: {issue}\n\n"
            f"=== ZONEWALK OUTPUT ===\n{zw_text[:2500]}\n\n"
            f"=== KB ARTICLES ===\n{kb_ctx_raw[:1500]}\n\n"
        )
        if quickrefs_raw:
            prompt += f"=== AVAILABLE COMMANDS ===\n{quickrefs_raw[:1500]}\n\n"
        if past_issues_raw:
            prompt += f"=== PAST ISSUES ===\n{past_issues_raw[:1500]}\n\n"
        if past_convs_raw:
            prompt += f"=== PAST CONVERSATIONS ===\n{past_convs_raw[:1500]}\n\n"
        prompt += (
            "Analyze the issue and provide:\n"
            "1. ROOT_CAUSE: What is the underlying problem?\n"
            "2. DRAFT_RESPONSE: A complete response for the customer\n"
            "3. ESCALATION: Whether this needs L2/L3 escalation"
        )
        ai_container = (
            '<div id="ai-analysis" style="background:#0f1729;border:1px solid #2563eb;border-radius:8px;padding:10px 12px;margin:8px 0">'
            '<b style="color:#60a5fa;font-size:12px">🤖 AI Analysis</b>'
            '<div id="ai-tokens" style="margin-top:4px;font-size:13px;color:#e2e8f0;white-space:pre-wrap;word-break:break-word;min-height:20px"></div>'
            '</div>'
        )
        yield _ssse("html", {"html": ai_container})

        full_response = ""
        async for token in _llm().chat_stream([{"role": "user", "content": prompt}]):
            full_response += token
            yield _ssse("token", {"text": token})

        parsed = '<div style="margin-top:4px;font-size:13px">'
        for para in full_response.split("\n\n"):
            p = para.strip()
            if p.startswith("ROOT_CAUSE:"):
                parsed += f'<div style="background:#1e3a5f;border-left:3px solid #2563eb;padding:8px 10px;margin:6px 0;border-radius:0 4px 4px 0"><b style="color:#60a5fa">Root Cause</b><div style="color:#e2e8f0;margin-top:2px">{esc(p[11:].strip())}</div></div>'
            elif p.startswith("DRAFT_RESPONSE:"):
                parsed += f'<div style="background:#0f2930;border-left:3px solid #16a34a;padding:8px 10px;margin:6px 0;border-radius:0 4px 4px 0"><b style="color:#4ade80">Draft Response</b><div style="color:#cbd5e1;margin-top:2px;white-space:pre-wrap">{esc(p[15:].strip())}</div></div>'
            elif p.startswith("CONFIDENCE:"):
                conf = p[11:].strip()
                ccol = "#4ade80" if "High" in conf else "#facc15" if "Medium" in conf else "#f87171"
                parsed += f'<div style="margin:4px 0;font-size:12px">Confidence: <span style="color:{ccol};font-weight:500">{esc(conf)}</span></div>'
            elif p.startswith("ESCALATION:"):
                ev = p[11:].strip()
                if "Yes" in ev or "L2" in ev or "L3" in ev:
                    parsed += f'<div style="background:#3b1a1a;border:1px solid #7f1d1d;border-radius:4px;padding:6px 10px;margin:4px 0;font-size:12px;color:#fca5a5">⚠ Needs escalation: {esc(ev)}</div>'
                else:
                    parsed += f'<div style="margin:4px 0;font-size:12px;color:#4ade80">✅ No escalation needed</div>'
            elif p:
                parsed += f'<div style="color:#cbd5e1;margin:4px 0">{esc(p)}</div>'
        parsed += '</div>'
        yield _ssse("replace_last", {"html": parsed})
    except Exception as e:
        logger.exception(f"AI analysis failed: {e}")
        yield _ssse("html", {"html": f'<div style="color:#f87171;padding:6px 0">⚠ AI analysis unavailable</div>'})

    # ── Zonewalk details ──
    if zw_text:
        yield _ssse("html", {"html": _fmt_zw_html(zw_text)})

    # ── KB articles ──
    if kb_hits:
        html_parts = ['<div style="margin:4px 0"><b>📚 Relevant KB articles:</b>']
        for h in kb_hits:
            html_parts.append(f'<div style="padding:3px 0 3px 12px;font-size:12px;color:#60a5fa">📄 {esc(h.get("title",""))}</div>')
        html_parts.append('</div>')
        yield _ssse("html", {"html": "".join(html_parts)})

    # ── Previous issues ──
    if domain_issues:
        html_parts = ['<div style="margin:4px 0"><b>📋 Previous issues for this domain:</b>']
        for i in domain_issues[:3]:
            html_parts.append(f'<div style="padding:2px 0 2px 12px;font-size:11px;color:#94a3b8">'
                f'#{i["id"]} [{i["status"]}] {esc(i.get("issue_type",""))}</div>')
        html_parts.append('</div>')
        yield _ssse("html", {"html": "".join(html_parts)})

    # ── Summary ──
    fail_count = zw_text.count("FAIL") + zw_text.count("MISSING")
    ok_count = zw_text.count("OK") + zw_text.count("PASS")
    warn_count = zw_text.count("WARN")

    summary_html = '<div style="margin-top:4px">'
    summary_html += '<div style="background:#1e293b;border-radius:8px;padding:10px 12px;margin:4px 0">'
    summary_html += '<b style="color:#f1f5f9;font-size:13px">📊 Diagnosis Summary</b>'
    summary_html += '<div style="display:flex;gap:10px;margin-top:6px;flex-wrap:wrap">'
    summary_html += f'<span style="color:#f87171;font-size:12px">🔴 {fail_count} issues</span>'
    summary_html += f'<span style="color:#4ade80;font-size:12px">🟢 {ok_count} passed</span>'
    if warn_count:
        summary_html += f'<span style="color:#facc15;font-size:12px">🟡 {warn_count} warnings</span>'
    summary_html += '</div>'

    suggestions = []
    if "NO_NS" in zw_text or "No NS records" in zw_text:
        suggestions.append("🔴 <b>No nameservers</b> — point the domain to ns1.hostserv.co.za / ns2.hostserv.co.za")
    if "NO_A_RECORD" in zw_text:
        suggestions.append("🔴 <b>No A record</b> — add an A record pointing to your server IP")
    if "NO_MX" in zw_text or "No MX records" in zw_text:
        suggestions.append("🔴 <b>No MX records</b> — add MX records for mail delivery")
    if "NO_SPF" in zw_text:
        suggestions.append("🟡 <b>Missing SPF</b> — add: <code>v=spf1 a mx include:relay.mailchannels.net ~all</code>")
    if "NO_DKIM" in zw_text:
        suggestions.append("🟡 <b>Missing DKIM</b> — configure DKIM signing on your mail server")
    if "NO_DMARC" in zw_text:
        suggestions.append("🟡 <b>Missing DMARC</b> — add a DMARC policy to control email handling")
    if "NOT_GRID" in zw_text:
        suggestions.append("ℹ️ <b>Not a 1-grid domain</b> — check with the domain registrar for DNS changes")
    if "SSL_EXP" in zw_text or "expired" in zw_text.lower():
        suggestions.append("🔴 <b>SSL cert expired</b> — renew immediately to avoid browser warnings")

    if suggestions:
        summary_html += '<div style="margin-top:8px;border-top:1px solid #334155;padding-top:6px">'
        summary_html += '<b style="color:#60a5fa;font-size:12px">💡 Suggestions:</b>'
        for s in suggestions:
            summary_html += f'<div style="font-size:12px;margin-top:4px;color:#cbd5e1">{s}</div>'
        summary_html += '</div>'

    if fail_count == 0:
        summary_html += '<div style="margin-top:8px;color:#4ade80;font-size:12px">✅ No issues found — domain looks healthy!</div>'
    else:
        summary_html += f'<div style="margin-top:8px;color:#94a3b8;font-size:11px">Found {fail_count} issue(s) — review the suggestions above or check the zonewalk details.</div>'

    summary_html += '</div></div>'
    yield _ssse("status", {"text": ""})
    yield _ssse("html", {"html": summary_html})
    summary_text = f"Domain {domain} diagnosed with {fail_count} issues"
    sessions.add_message(session_id, "assistant", summary_text)

    # ── Log everything from this diagnosis ──
    await _log_exchange(session_id, f"{domain} {issue}", summary_text,
                        domain, ["zonewalk", "kb_search", "history_check", "ai_analysis"],
                        zw_text=zw_text[:500])

    yield _ssse("done", {})


@app.post("/chat/stream")
async def chat_stream(message: str = Form(...), session_id: str = Form(...)):
    return StreamingResponse(
        _handle_chat_stream(message, session_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )

# ── HISTORY ──

@app.post("/views/history/search")
async def history_search(q: str = Form("")):
    tickets_data = warehouse.search_tickets(q, 20)
    conv_data = warehouse.search_conversations_by_domain(q, 10)
    if not tickets_data and not conv_data:
        return HTMLResponse('<div class="empty">No results found for this domain</div>')
    html = ""
    if tickets_data:
        html += '<div class="section-label">Tickets</div>'
        for t in tickets_data:
            html += f'''<div class="card clickable" onclick="htmx.ajax('GET','/views/ticket/{esc(t.get("ticket_ref","?"))}',{{target:'#panel',swap:'innerHTML'}})">
              <div class="title">#{esc(t.get("ticket_ref","?"))} {esc(t.get("domain",""))}</div>
              <div class="meta"><span>📅 {esc(t.get("created_at",""))}</span><span>🏷️ {esc(t.get("category",""))}</span><span>📌 {esc(t.get("outcome",""))}</span></div>
              <div class="preview">{esc((t.get("description","") or "")[:200])}</div>
            </div>'''
    if conv_data:
        html += '<div class="section-label" style="margin-top:12px">Conversations</div>'
        for c in conv_data:
            msg = c.get("content","") or c.get("message","") or ""
            ts = esc(c.get("timestamp",""))
            dom = esc(c.get("metadata",{}).get("domain","") or c.get("domain",""))
            ctype = "💬" if c.get("_conv_type") == "conversation" else "🗣️"
            html += f'''<div class="card" style="margin-bottom:4px">
              <div class="title">{ctype} {esc(dom)}</div>
              <div class="meta"><span>📅 {ts}</span></div>
              <div class="preview">{esc(msg[:300])}</div>
            </div>'''
    return HTMLResponse(html)

@app.get("/views/ticket/{ref}")
async def ticket_detail(ref: str):
    tickets_data = warehouse.search_tickets(ref, 5)
    t = None
    for ti in tickets_data:
        if str(ti.get("ticket_ref","")) == ref:
            t = ti; break
    if not t and tickets_data:
        t = tickets_data[0]
    if not t:
        return HTMLResponse('<div class="empty">Ticket not found</div>')
    html = f'''<div class="article-view">
      <span class="back" hx-get="/views/history" hx-target="#panel" hx-swap="innerHTML">← Back</span>
      <h2>#{esc(t.get("ticket_ref","?"))} {esc(t.get("domain",""))}</h2>
      <div class="cat">{esc(t.get("category",""))}{" / "+esc(t.get("sub_category","")) if t.get("sub_category") else ""} · {esc(t.get("outcome",""))} · {esc(t.get("created_at",""))}</div>
      <div class="cat">Server: {esc(t.get("server_ip",""))} · PTR: {esc(t.get("ptr",""))}</div>
      <div class="body">{esc(t.get("description","No description"))}</div>
    </div>'''
    return HTMLResponse(html)

# ── KB ──

@app.post("/views/kb/search")
async def kb_search_view(q: str = Form("")):
    if not q:
        return HTMLResponse('<div class="empty">Type a search term to find articles</div>')
    results = warehouse.search_kb(q, 15)
    if not results:
        return HTMLResponse('<div class="empty">No articles found</div>')
    html = ""
    for r in results:
        title = esc(r.get("title",""))
        cat = esc(r.get("category","General"))
        content = esc((r.get("content","") or "")[:200])
        url_title = esc(r.get("title","").replace("'","%27"))
        html += f'''<div class="card clickable" hx-get="/views/kb/detail?title={url_title}" hx-target="#panel" hx-swap="innerHTML">
          <div class="title">{title}</div>
          <div class="meta"><span>📂 {cat}</span></div>
          <div class="preview">{content}</div>
        </div>'''
    return HTMLResponse(html)

@app.get("/views/kb/detail")
async def kb_detail_view(title: str = ""):
    if not title:
        return HTMLResponse('<div class="empty">No article specified</div>')
    article = warehouse.get_kb_article(title)
    if not article:
        return HTMLResponse(f'<div class="empty">Article "{esc(title)}" not found</div>')
    atitle = esc(article.get("title",""))
    acat = esc(article.get("category","General"))
    acontent = esc(article.get("content",""))
    lines = [l.strip() for l in acontent.split("\n")]
    html = f'''<div class="article-view">
      <span class="back" hx-get="/views/kb" hx-target="#panel" hx-swap="innerHTML">← Back to KB</span>
      <h2>{atitle}</h2>
      <div class="cat">📂 {acat}</div>
      <div class="body">'''
    para = []
    for t in lines:
        if not t:
            if para:
                html += f'<p style="margin:8px 0;font-size:13px;line-height:1.7">{esc(" ".join(para))}</p>'
                para = []
            continue
        if t.isupper() and len(t) > 10 and not t.startswith("HTTP") and not t.startswith("Q."):
            if para:
                html += f'<p style="margin:8px 0;font-size:13px;line-height:1.7">{esc(" ".join(para))}</p>'
                para = []
            html += f'<h3 style="margin:18px 0 6px;font-size:14px;color:#a5b4fc">{esc(t)}</h3>'
        elif t.startswith(("IMPORTANT:", "NOTE:")):
            if para:
                html += f'<p style="margin:8px 0;font-size:13px;line-height:1.7">{esc(" ".join(para))}</p>'
                para = []
            html += f'<div style="background:#1e293b;border-left:3px solid #facc15;padding:8px 12px;margin:8px 0;border-radius:4px;font-size:13px">{esc(t)}</div>'
        elif t.startswith("TIP:"):
            if para:
                html += f'<p style="margin:8px 0;font-size:13px;line-height:1.7">{esc(" ".join(para))}</p>'
                para = []
            html += f'<div style="background:#1e293b;border-left:3px solid #22c55e;padding:8px 12px;margin:8px 0;border-radius:4px;font-size:13px">{esc(t)}</div>'
        elif t.startswith(("- ", "• ", "✓", "✗")):
            if para:
                html += f'<p style="margin:8px 0;font-size:13px;line-height:1.7">{esc(" ".join(para))}</p>'
                para = []
            html += f'<div style="padding-left:16px;margin:3px 0;font-size:13px">{esc(t)}</div>'
        else:
            para.append(t)
    if para:
        html += f'<p style="margin:8px 0;font-size:13px;line-height:1.7">{esc(" ".join(para))}</p>'
    html += '''</div></div>'''
    return HTMLResponse(html)

# ── TICKETS ──

@app.post("/views/tickets/search")
async def tickets_search(q: str = Form("")):
    tickets_data = warehouse.search_tickets(q, 30)
    if not tickets_data:
        return HTMLResponse('<div class="empty">No tickets found</div>')
    html = ""
    for t in tickets_data:
        html += f'''<div class="card clickable" onclick="htmx.ajax('GET','/views/ticket/{esc(t.get("ticket_ref","?"))}',{{target:'#panel',swap:'innerHTML'}})">
          <div class="title">#{esc(t.get("ticket_ref","?"))} {esc(t.get("domain",""))}</div>
          <div class="meta"><span>📅 {esc(t.get("created_at",""))}</span><span>🏷️ {esc(t.get("category",""))}</span><span>📌 {esc(t.get("outcome",""))}</span></div>
          <div class="preview">{esc((t.get("description","") or "")[:200])}</div>
        </div>'''
    return HTMLResponse(html)

# ── ZONEWALK ──

@app.post("/views/zonewalk/run")
async def zonewalk_run(domain: str = Form(...), deep: str = Form("false")):
    is_deep = deep.lower() == "true"
    try:
        result = run_zonewalk_full(domain, deep=is_deep, ports=True, reputation=True)
        d = result.to_dict()
    except Exception as e:
        return HTMLResponse('<div class="empty" style="padding:20px;margin-top:12px">Error: ' + esc(str(e)) + '</div>')

    # Log usage
    try:
        warehouse.log_usage("zonewalk", domain, {"domain": domain, "deep": is_deep})
    except:
        pass

    # ── Enhance subdomains with online/SSL checks (deep only) ──
    if is_deep and d.get("subdomains"):
        enhanced = []
        for sd in d["subdomains"][:15]:
            sub = sd.get("subdomain","")
            try:
                http_s, https_s, ssl_d = http_check(sub, timeout=5)
                sd["http_ok"] = http_s.get("status_code") if http_s else None
                sd["https_ok"] = https_s.get("status_code") if https_s else None
                sd["ssl_days"] = ssl_d
            except:
                sd["http_ok"] = None
                sd["https_ok"] = None
                sd["ssl_days"] = None
            enhanced.append(sd)
        d["subdomains"] = enhanced

    # ── Mail analysis ──
    mail_info = {"mx_servers": [], "mail_a_records": [], "mail_ports": {}, "hosted_elsewhere": False, "mail_host": "", "mail_domain_a": [], "mail_domain_ptr": None}
    if d.get("mx_records"):
        mail_info["mx_servers"] = [m[1] for m in d["mx_records"]]
        for mx in d["mx_records"]:
            mx_host = mx[1].rstrip(".")
            try:
                res = Resolver()
                a_recs = res.a(mx_host)
                mail_info["mail_a_records"] = a_recs
                mail_info["mail_host"] = mx_host
                # Check if mx IP matches any domain A record IP
                domain_ips = set(d.get("a_records", []))
                mx_ips = set(a_recs)
                mail_info["hosted_elsewhere"] = not bool(domain_ips & mx_ips) if domain_ips and mx_ips else False
            except:
                pass
            break  # Just check primary MX
    # Check mail ports on domain
    mail_ports_to_check = [(25,"SMTP"),(465,"SMTPS"),(587,"MSA"),(993,"IMAPS"),(995,"POP3S")]
    for port, name in mail_ports_to_check:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            r = s.connect_ex((domain, port))
            mail_info["mail_ports"][name] = "open" if r == 0 else "closed"
            s.close()
        except:
            mail_info["mail_ports"][name] = "error"

    # Check mail.domain A + PTR
    mail_domain = f"mail.{domain}"
    try:
        md_res = Resolver()
        md_a = md_res.a(mail_domain)
        mail_info["mail_domain_a"] = md_a
        if md_a:
            md_ptr = md_res.ptr(md_a[0])
            mail_info["mail_domain_ptr"] = md_ptr
    except:
        pass

    # ── Build summary items ──
    summary = []

    if not d.get("is_grid"):
        prov = esc(d.get("hosting_provider","an external provider"))
        impact = "DNS records managed externally — we cannot modify them. Client must update DNS at their provider."
        if "Cloudflare" in (d.get("hosting_provider","")):
            impact = "Cloudflare proxies traffic. We cannot see origin server directly. Client must disable proxy (orange cloud) in Cloudflare dashboard for us to diagnose."
        summary.append(("warn", "🏢 Not hosted with 1-grid", prov + ". " + impact))

    if not d.get("spf_record"):
        summary.append(("error", "📧 Missing SPF record", "Email may be flagged as spam or rejected. Authorized senders only if SPF published."))
    if not d.get("dkim_records"):
        summary.append(("warn", "📧 Missing DKIM", "Emails may fail DKIM checks. Receiving servers may quarantine or reject."))
    dmarc_rec = d.get("dmarc_record")
    if not dmarc_rec:
        summary.append(("warn", "📧 Missing DMARC", "No policy on how receivers handle unauthenticated email — spoofing possible."))
    elif "p=none" in dmarc_rec.lower():
        summary.append(("warn", "📧 DMARC p=none", "Policy set to 'none' — monitoring only, no protection against spoofing."))

    ssl = d.get("ssl_expiry_days")
    if ssl is not None and ssl < 30:
        level = "error" if ssl < 7 else "warn"
        label = "🔒 SSL expiring" if ssl > 0 else "🔒 SSL EXPIRED"
        imp = " Browsers will show 'Not Secure' warning. Email delivery may fail." if ssl < 0 else " Renew soon to avoid service disruption."
        summary.append((level, label, str(abs(ssl)) + " day" + ("s" if abs(ssl)!=1 else "") + (" overdue." if ssl<0 else " remaining.") + imp))

    if d.get("ptr_record") and d.get("a_records"):
        if d.get("ptr_record", "").lower().find(domain.split(".")[0].lower()) < 0:
            summary.append(("warn", "🔗 PTR mismatch", "Reverse DNS (" + esc(d.get("ptr_record","")) + ") does not match domain. Some mail servers may reject email."))

    # Mail hosting analysis
    if mail_info.get("hosted_elsewhere"):
        summary.append(("info", "📨 Mail hosted externally", "Mail server (" + esc(mail_info.get("mail_host","")) + ") is on different infrastructure than the website. Changes to web DNS won't affect mail."))

    if d.get("open_ports"):
        unusual = [p for p in d["open_ports"] if p[0] not in (21,22,25,53,80,110,143,443,465,587,993,995,3306,8443)]
        if unusual:
            names = ", ".join(esc(str(p[0])) + "/" + esc(p[1]) for p in unusual[:5])
            summary.append(("warn", "🔌 Unusual open ports", names + ". May indicate unauthorized services or compromise risk."))

    if d.get("blocklists"):
        listed_bl = [b for b in d["blocklists"] if b.get("listed")]
        if listed_bl:
            summary.append(("error", "🛡️ Listed on " + str(len(listed_bl)) + " blocklist" + ("s" if len(listed_bl)!=1 else ""), "Email delivery likely affected. Client must request delisting. Lists: " + ", ".join(esc(b["list"]) for b in listed_bl[:4])))

    if d.get("issues"):
        for iss in d["issues"][:5]:
            sev = "error" if iss.startswith(("NO_","HTTP_5","SSL_EXP","BLOCKLIST")) else "warn"
            summary.append((sev, "⚠ " + esc(iss[:60]), ""))

    # Check warehouse for known issues on this server
    if d.get("a_records"):
        ticket_hits = warehouse.search_tickets(domain, 3)
        if ticket_hits:
            outcomes = set(t.get("outcome","") for t in ticket_hits if t.get("outcome"))
            if outcomes:
                summary.append(("info", "📋 Known from history", "Past tickets for this domain: " + ", ".join(esc(o) for o in list(outcomes)[:3])))

    # Save full zonewalk result to MongoDB for AI reference
    try:
        warehouse.save_zonewalk_result(domain, d)
    except Exception:
        pass

    # ── Left column: full results with section anchors ──
    sections = []
    left = ''
    sidx = 0

    # Section helper
    def add_section(sid, label, content, default_open=False):
        nonlocal left, sidx
        disp = "block" if default_open else "none"
        left += '<div id="zw-section-' + sid + '" class="zw-section" style="display:' + disp + ';scroll-margin-top:4px">'
        left += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">'
        left += '<span style="font-size:10px;color:#64748b;font-weight:600">' + "{:02d}".format(sidx) + '</span>'
        left += '<span style="font-size:11px;color:#94a3b8;font-weight:600;text-transform:uppercase;letter-spacing:0.05em">' + label + '</span>'
        left += '</div>'
        left += content
        left += '</div>'
        sections.append((sid, label))
        sidx += 1

    # Provider header
    provider = esc(d.get("hosting_provider","Unknown") if not d.get("is_grid") else "1-grid")
    domain_label = esc(d.get("domain",""))
    htype = esc(d.get("hosting_type",""))
    htype_tag = '<span style="font-size:13px;color:#64748b;background:#1e293b;padding:3px 10px;border-radius:12px">' + htype + '</span>' if htype else ""
    bgcolor = "#1e3a5f" if d.get("is_grid") else "#3b1f1f"
    fgcolor = "#93c5fd" if d.get("is_grid") else "#fca5a5"
    header = '<div style="display:flex;align-items:center;gap:8px;background:#0f1729;border:1px solid #1e293b;border-radius:6px;padding:6px 12px;margin-bottom:6px">'
    header += '<span style="background:' + bgcolor + ';color:' + fgcolor + ';padding:3px 10px;border-radius:20px;font-size:13px;font-weight:600;white-space:nowrap">' + provider + '</span>'
    header += '<span style="font-size:16px;font-weight:500">' + domain_label + '</span>'
    header += htype_tag
    header += '</div>'
    left += header

    # 1. Nameservers
    ns_html = ''
    if d.get("nameservers"):
        for ns in d["nameservers"]:
            ns_html += '<div style="background:#0f1729;border:1px solid #1e293b;border-radius:5px;padding:6px 10px;margin-bottom:2px;font-family:monospace;font-size:12px">' + esc(ns) + '</div>'
    else:
        ns_html = '<div class="empty" style="padding:8px">No nameservers resolved</div>'
    if ns_html:
        add_section("ns", "Nameservers", ns_html, default_open=True)

    # 2. DNS Records
    dns_html = '<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:14px;background:#0f1729;border:1px solid #1e293b;border-radius:8px;padding:12px 16px">'
    dns_html += '<span style="color:#94a3b8">A Record</span><span style="font-family:monospace;color:' + ("#f87171" if not d.get("a_records") else "#e2e8f0") + '">' + (esc(", ".join(d["a_records"])) if d.get("a_records") else "NONE") + '</span>'
    ptr_val = esc(d.get("ptr_record", "")) if d.get("ptr_record") else "No PTR"
    ptr_col = "#f87171" if not d.get("ptr_record") else "#4ade80" if domain.split(".")[0].lower() in d.get("ptr_record","").lower() else "#facc15"
    dns_html += '<span style="color:#94a3b8">PTR</span><span style="font-family:monospace;color:' + ptr_col + '">' + ptr_val + '</span>'
    if mail_info.get("mail_domain_a"):
        md_ptr = esc(mail_info.get("mail_domain_ptr","")) if mail_info.get("mail_domain_ptr") else "No PTR"
        md_ptr_col = "#f87171" if not mail_info.get("mail_domain_ptr") else "#4ade80"
        dns_html += '<span style="color:#94a3b8">mail PTR</span><span style="font-family:monospace;color:' + md_ptr_col + '">' + md_ptr + '</span>'
    if d.get("mx_records"):
        for mx in d["mx_records"]:
            dns_html += '<span style="color:#94a3b8">MX</span><span style="font-family:monospace">' + esc(mx[1]) + ' (prio ' + str(mx[0]) + ')</span>'
    if d.get("soa"):
        dns_html += '<span style="color:#94a3b8">SOA</span><span style="font-family:monospace">' + esc(d["soa"].get("mname","")) + ' · serial ' + esc(str(d["soa"].get("serial","?"))) + '</span>'
    dns_html += '</div>'
    add_section("dns", "DNS Records", dns_html)

    # 3. Mail Authentication
    mailauth_html = '<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:14px;background:#0f1729;border:1px solid #1e293b;border-radius:8px;padding:12px 16px">'

    # SPF
    spf_ok = bool(d.get("spf_record"))
    spf_grid = d.get("spf_record") and "mailchannels" in d["spf_record"].lower()
    spf_tick = '<span style="color:#4ade80;font-size:12px"> ✓ 1-grid</span>' if spf_grid else ''
    spf_trunc = esc(d["spf_record"][:80]) + ('…' if len(d.get("spf_record","")) > 80 else '') if d.get("spf_record") else ''
    mailauth_html += '<span style="color:#94a3b8">SPF</span><span style="color:' + ("#4ade80" if spf_ok else "#f87171") + ';font-weight:500">' + ("OK" if spf_ok else "MISSING") + spf_tick + '</span>'
    if spf_trunc:
        mailauth_html += '<span style="color:#94a3b8"></span><span style="font-family:monospace;font-size:11px;color:#64748b;word-break:break-all">' + spf_trunc + '</span>'

    # DKIM
    dkim_ok = bool(d.get("dkim_records"))
    dkim_trunc = esc(d["dkim_records"][0][:80]) + ('…' if len(d.get("dkim_records",[""])) > 80 else '') if d.get("dkim_records") else ''
    mailauth_html += '<span style="color:#94a3b8">DKIM</span><span style="color:' + ("#4ade80" if dkim_ok else "#f87171") + ';font-weight:500">' + ("OK" if dkim_ok else "MISSING") + '</span>'
    if dkim_trunc:
        mailauth_html += '<span style="color:#94a3b8"></span><span style="font-family:monospace;font-size:11px;color:#64748b;word-break:break-all">' + dkim_trunc + '</span>'

    # DMARC
    dmarc_rec = d.get("dmarc_record")
    dmarc_none = dmarc_rec and "p=none" in dmarc_rec.lower()
    dmarc_good = dmarc_rec and any(p in dmarc_rec.lower() for p in ["p=quarantine", "p=reject"])
    if dmarc_good:
        dmarc_label, dmarc_col = "OK", "#4ade80"
    elif dmarc_rec and dmarc_none:
        dmarc_label, dmarc_col = "WEAK (p=none)", "#facc15"
    elif dmarc_rec:
        dmarc_label, dmarc_col = "OK", "#4ade80"
    else:
        dmarc_label, dmarc_col = "MISSING", "#f87171"
    dmarc_tick = '<span style="color:#4ade80;font-size:12px"> ✓ 1-grid</span>' if dmarc_good else ''
    dmarc_trunc = esc(dmarc_rec[:80]) + ('…' if len(dmarc_rec) > 80 else '') if dmarc_rec else ''
    mailauth_html += '<span style="color:#94a3b8">DMARC</span><span style="color:' + dmarc_col + ';font-weight:500">' + dmarc_label + dmarc_tick + '</span>'
    if dmarc_trunc:
        mailauth_html += '<span style="color:#94a3b8"></span><span style="font-family:monospace;font-size:11px;color:#64748b;word-break:break-all">' + dmarc_trunc + '</span>'

    if d.get("has_mailchannels"):
        mailauth_html += '<span style="color:#94a3b8">MailChannels</span><span style="color:#4ade80;font-weight:500">✓ Authorised</span>'
    mailauth_html += '</div>'
    add_section("mailauth", "Mail Auth", mailauth_html)

    # Detect 1-grid mail infrastructure
    mail_platform = ""
    if mail_info.get("mail_host"):
        mh = mail_info["mail_host"].lower()
        if "titan" in mh:
            mail_platform = "Titan (inbound)"
        elif "gridhosted" in mh or "1-grid" in mh:
            mail_platform = "1-grid Mail"
        elif d.get("has_mailchannels"):
            mail_platform = "MailChannels (outbound)"
        else:
            mail_platform = "External"

    # 4. Mail Analysis (new)
    mail_html = '<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:14px;background:#0f1729;border:1px solid #1e293b;border-radius:8px;padding:12px 16px">'
    if mail_info.get("mail_host"):
        mail_html += '<span style="color:#94a3b8">Mail Server</span><span style="font-family:monospace">' + esc(mail_info["mail_host"]) + '</span>'
        mail_html += '<span style="color:#94a3b8">MX IPs</span><span style="font-family:monospace">' + esc(", ".join(mail_info.get("mail_a_records",[]))) + '</span>'
        mail_html += '<span style="color:#94a3b8">MX PTR</span><span style="font-family:monospace;color:' + ("#4ade80" if mail_info.get("mail_domain_ptr") else "#f87171") + '">' + (esc(mail_info["mail_domain_ptr"]) if mail_info.get("mail_domain_ptr") else "No PTR") + '</span>'
        mail_plat_col = "#4ade80" if mail_platform in ("Titan (inbound)", "1-grid Mail", "MailChannels (outbound)") else "#facc15"
        mail_html += '<span style="color:#94a3b8">Platform</span><span style="color:' + mail_plat_col + ';font-weight:500">' + mail_platform + '</span>'
        mail_html += '<span style="color:#94a3b8">Separate infra</span><span style="color:' + ("#facc15" if mail_info.get("hosted_elsewhere") else "#4ade80") + ';font-weight:500">' + ("Yes — mail external" if mail_info.get("hosted_elsewhere") else "No — same as web") + '</span>'
    else:
        mail_html += '<span style="color:#94a3b8">MX</span><span style="color:#f87171;font-weight:500">No MX records</span>'
    mail_html += '</div>'
    mail_html += '<div style="margin-top:6px;font-size:14px;background:#0f1729;border:1px solid #1e293b;border-radius:8px;padding:12px 16px">'
    mail_html += '<div style="font-size:11px;color:#64748b;margin-bottom:6px">Mail Ports</div>'
    mail_html += '<div style="display:flex;flex-wrap:wrap;gap:4px">'
    for pname, pstatus in mail_info["mail_ports"].items():
        c = "#4ade80" if pstatus == "open" else "#f87171" if pstatus == "closed" else "#94a3b8"
        mail_html += '<span style="background:#1e293b;border:1px solid #334155;padding:4px 10px;border-radius:6px;font-size:11px;color:' + c + '">' + pname + ": " + pstatus + '</span>'
    mail_html += '</div></div>'
    add_section("mail", "Mail Analysis", mail_html)

    # 5. Web / SSL
    web_html = ""
    if d.get("http_status") or d.get("https_status"):
        web_html = '<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:14px;background:#0f1729;border:1px solid #1e293b;border-radius:8px;padding:12px 16px">'
        if d.get("http_status"):
            code = d["http_status"].get("status_code","?")
            c = "#f87171" if code >= 400 else "#facc15" if code >= 300 else "#4ade80"
            web_html += '<span style="color:#94a3b8">HTTP</span><span style="color:' + c + ';font-weight:500">' + str(code) + '</span>'
        if d.get("https_status"):
            code = d["https_status"].get("status_code","?")
            c = "#f87171" if code >= 400 else "#facc15" if code >= 300 else "#4ade80"
            web_html += '<span style="color:#94a3b8">HTTPS</span><span style="color:' + c + ';font-weight:500">' + str(code) + '</span>'
        ssl = d.get("ssl_expiry_days")
        if ssl is not None:
            c = "#f87171" if ssl < 14 else "#facc15" if ssl < 60 else "#4ade80"
            txt = "EXPIRED" if ssl < 0 else str(ssl) + " days"
            web_html += '<span style="color:#94a3b8">SSL</span><span style="color:' + c + ';font-weight:500">' + txt + '</span>'
        ssl_issuer = d.get("ssl_issuer")
        if ssl_issuer:
            web_html += '<span style="color:#94a3b8">Issuer</span><span style="font-size:13px;color:#94a3b8">' + esc(ssl_issuer) + '</span>'
        web_html += '</div>'
    else:
        web_html = '<div class="empty" style="padding:8px">No web server detected</div>'
    add_section("web", "Web / SSL", web_html)

    # 6. Open Ports
    ports_html = ""
    if d.get("open_ports"):
        ports_html = '<div style="display:flex;flex-wrap:wrap;gap:4px">'
        for p in d["open_ports"]:
            ports_html += '<span style="background:#1e293b;border:1px solid #334155;padding:4px 10px;border-radius:6px;font-size:11px">' + esc(str(p[0])) + '/' + esc(p[1]) + '</span>'
        ports_html += '</div>'
    else:
        ports_html = '<div class="empty" style="padding:8px">No open ports found (scan may be blocked)</div>'
    add_section("ports", "Open Ports", ports_html)

    # 7. DNS Propagation
    if d.get("propagation"):
        prop_html = ""
        for p in d["propagation"]:
            match = p.get("match", False)
            c = "#4ade80" if match else "#f87171"
            prop_html += '<div style="display:grid;grid-template-columns:24px 1fr;gap:2px 8px;background:#0f1729;border:1px solid #1e293b;border-radius:6px;padding:8px 12px;margin-bottom:3px">'
            prop_html += '<span style="color:' + c + '">' + ("✓" if match else "✗") + '</span>'
            prop_html += '<div><div style="font-size:12px">' + esc(p.get("resolver","")) + '</div><div style="font-size:11px;color:#64748b">' + p.get("ip","") + ' · ' + (", ".join(p.get("result",[])) if p.get("result") else "NONE") + '</div></div>'
            prop_html += '</div>'
        add_section("prop", "DNS Propagation", prop_html)

    # 8. Subdomains (all common, with ✓/✗)
    found_lookup = {}
    for sd in d.get("subdomains", []):
        found_lookup[sd.get("subdomain","").lower()] = sd
    sub_html = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px">'
    for sname in COMMON_SUBDOMAINS:
        target = f"{sname}.{domain}".lower()
        if target in found_lookup:
            sd = found_lookup[target]
            info_parts = []
            if sd.get("ips"):
                info_parts.append(", ".join(sd["ips"]))
            if sd.get("cname"):
                info_parts.append("CNAME: " + sd["cname"])
            sub_html += '<div style="background:#0f1729;border:1px solid #1e4a1e;border-radius:5px;padding:5px 8px">'
            sub_html += '<span style="color:#4ade80">✓</span> <span style="font-family:monospace;font-size:12px;color:#e2e8f0">' + esc(sname) + '</span>'
            if info_parts:
                sub_html += '<div style="font-size:11px;color:#94a3b8;margin-top:1px">' + esc("; ".join(info_parts)) + '</div>'
            sub_html += '</div>'
        elif d.get("subdomains") is not None:
            sub_html += '<div style="background:#0f1729;border:1px solid #1e293b;border-radius:5px;padding:5px 8px">'
            sub_html += '<span style="color:#f87171">✗</span> <span style="font-family:monospace;font-size:12px;color:#64748b">' + esc(sname) + '</span>'
            sub_html += '</div>'
        else:
            sub_html += '<div style="background:#0f1729;border:1px solid #1e293b;border-radius:5px;padding:5px 8px">'
            sub_html += '<span style="color:#475569">–</span> <span style="font-family:monospace;font-size:12px;color:#475569">' + esc(sname) + '</span>'
            sub_html += '</div>'
    sub_html += '</div>'
    add_section("subs", "Subdomains", sub_html)

    # 9. WHOIS
    if d.get("whois") and d["whois"].get("registrar"):
        whois_html = '<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:14px;background:#0f1729;border:1px solid #1e293b;border-radius:8px;padding:12px 16px">'
        whois_html += '<span style="color:#94a3b8">Registrar</span><span>' + esc(d["whois"]["registrar"]) + '</span>'
        if d["whois"].get("expiry"):
            whois_html += '<span style="color:#94a3b8">Expiry</span><span>' + esc(d["whois"]["expiry"]) + '</span>'
        whois_html += '</div>'
        add_section("whois", "WHOIS", whois_html)

    # 10. IP Reputation (all databases with ✓/✗)
    bl_by_name = {b.get("list",""): b.get("listed", False) for b in d.get("blocklists", [])}
    bl_html = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px">'
    for _bl_host, bl_name in BLACKLISTS:
        listed = bl_by_name.get(bl_name, None)
        if listed is True:
            bl_html += '<div style="background:#2d1b1b;border:1px solid #5c1a1a;border-radius:5px;padding:5px 8px;font-size:11px">'
            bl_html += '<span style="color:#f87171">✗</span> <span style="color:#fca5a5;margin-left:3px">' + esc(bl_name) + '</span>'
            bl_html += '</div>'
        else:
            bl_html += '<div style="background:#1a2e1a;border:1px solid #1e4a1e;border-radius:5px;padding:5px 8px;font-size:11px">'
            bl_html += '<span style="color:#4ade80">✓</span> <span style="color:#86efac;margin-left:3px">' + esc(bl_name) + '</span>'
            bl_html += '</div>'
    bl_html += '</div>'
    add_section("bl", "IP Reputation", bl_html)

    # ── Right column: summary card ──
    right = '<div style="background:#0f1729;border:1px solid #1e293b;border-radius:10px;padding:16px">'
    right += '<div style="font-size:13px;font-weight:600;color:#e2e8f0;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #1e293b">📋 Summary</div>'
    if not summary:
        right += '<div style="font-size:13px;color:#4ade80;padding:6px 0">✓ No issues detected</div>'
    else:
        for sev, title, detail in summary:
            bg = {"error":"#2d1b1b","warn":"#2d2418","info":"#1a2438"}.get(sev, "#1e293b")
            bc = {"error":"#5c1a1a","warn":"#5c3a1a","info":"#1e3a5f"}.get(sev, "#334155")
            dot = {"error":"#f87171","warn":"#facc15","info":"#60a5fa"}.get(sev, "#94a3b8")
            right += '<div style="background:' + bg + ';border:1px solid ' + bc + ';border-radius:6px;padding:8px 10px;margin-bottom:6px">'
            right += '<div style="display:flex;align-items:start;gap:6px">'
            right += '<span style="color:' + dot + ';font-size:11px;margin-top:2px">●</span>'
            right += '<div><div style="font-size:13px;font-weight:500;color:#e2e8f0">' + title + '</div>'
            if detail:
                right += '<div style="font-size:12px;color:#94a3b8;margin-top:2px">' + detail + '</div>'
            right += '</div></div></div>'
    right += '</div>'

    # ── Secondary left nav ──
    nav = '<div style="background:#0f1729;border:1px solid #1e293b;border-radius:10px;padding:10px">'
    nav += '<div style="font-size:11px;color:#475569;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px;padding-left:4px">Sections</div>'
    for sid, label in sections:
        nav += '<div onclick="zwShow(\'' + sid + '\')" style="cursor:pointer;padding:5px 8px;font-size:12px;color:#94a3b8;text-decoration:none;border-radius:4px;transition:all .1s" onmouseover="this.style.background=\'#1e293b\'" onmouseout="this.style.background=\'transparent\'">'
        nav += label
        nav += '</div>'
    nav += '</div>'

    # ── Combine: nav | left+right ──
    html = '<div style="display:grid;grid-template-columns:110px 1fr 288px;gap:6px;align-items:start">'
    html += '<div style="position:sticky;top:12px">' + nav + '</div>'
    html += '<div>' + left + '</div>'
    html += '<div style="position:sticky;top:12px">' + right + '</div>'
    html += '</div>'
    html += '''<script>
function zwShow(id) {
  var sections = document.querySelectorAll('.zw-section');
  sections.forEach(function(s){ s.style.display = 'none'; });
  var el = document.getElementById('zw-section-' + id);
  if (el) el.style.display = 'block';
}
</script>'''
    return HTMLResponse(html)

# ── HEADERS ──

@app.post("/views/headers/analyze")
async def headers_analyze(headers: str = Form(...)):
    try:
        d = parse_email_headers(headers)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')

    html = ""
    if d.get("block_reason"):
        html += f'<div class="card" style="border-color:#ef4444;margin-bottom:8px"><div class="title" style="color:#f87171">⛔ Block Detected</div><div class="val" style="color:#fca5a5">{esc(d["block_reason"])}</div></div>'

    html += '<div class="section-label">Header Fields</div><div class="details-grid" style="margin-bottom:8px">'
    for k in ["from","to","subject","date","return_path","reply_to","originating_ip","spam_score"]:
        v = d.get(k)
        if v:
            html += f'<span class="k">{k.replace("_"," ").title()}</span><span class="v mono">{esc(str(v))}</span>'
    html += '</div>'

    html += '<div class="section-label">Authentication</div><div class="details-grid" style="margin-bottom:8px">'
    for k in ["spf_result","dkim_result","dmarc_result","arc_result"]:
        v = d.get(k)
        if v:
            cls = "green" if str(v).lower() == "pass" else "red"
            html += f'<span class="k">{k.replace("_result","").upper()}</span><span class="v {cls}">{esc(str(v))}</span>'
    html += '</div>'

    hops = d.get("hops", [])
    if hops:
        html += f'<div class="section-label">Received Chain ({len(hops)} hops)</div>'
        for i, h in enumerate(hops):
            label = "Origin" if i == 0 else "Final" if i == len(hops)-1 else f"Hop {i+1}"
            html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div style="font-size:10px;color:#64748b;margin-bottom:2px">{label}</div><div class="val mono" style="font-size:11px">{esc(str(h)[:200])}</div></div>'

    return HTMLResponse(html)

# ── PROPAGATION ──

@app.post("/views/propagation/check")
async def propagation_check_view(domain: str = Form(...)):
    try:
        res = Resolver()
        a_records = res.a(domain)
        if not a_records:
            return HTMLResponse(f'<div class="empty">No A records found for {esc(domain)}</div>')
        prop = check_propagation(domain, a_records)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')

    html = f'<div class="card" style="margin-bottom:8px"><div class="title">📡 {esc(domain)}</div><div class="meta">A records: {esc(", ".join(a_records))}</div></div>'
    if prop:
        html += '<div class="prop-grid">'
        for p in prop:
            cls = "green" if p.get("match") else "red"
            html += f'''<div class="prop-item">
              <div class="rname">{esc(p.get("resolver",""))} {"✓" if p.get("match") else "✗"}</div>
              <div class="rip">{p.get("ip","")}</div>
              <div class="rresult {cls}">{(p.get("result") and ", ".join(p["result"])) or "NONE"}</div>
            </div>'''
        html += '</div>'
    return HTMLResponse(html)

# ── NAMESERVERS ──

@app.post("/views/nameservers/check")
async def nameservers_check_view(domain: str = Form(...)):
    try:
        res = Resolver()
        ns = res.ns(domain)
        provider = "Unknown"; is_grid = False; hosting_type = ""
        for ns_host in ns:
            for pattern, htype in GRID_NS_PATTERNS.items():
                if pattern in ns_host.lower():
                    provider = "1-grid"; is_grid = True; hosting_type = htype; break
            if is_grid: break
        if not is_grid:
            for pattern, name in COMPETITORS:
                if any(pattern in n.lower() for n in ns):
                    provider = name; break
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')

    cls = "grid" if is_grid else "external"
    label = "1-grid" if is_grid else provider
    html = f'''<div class="detect-box" style="margin-bottom:8px">
      <span class="badge {cls}">{esc(label)}</span>
      <span style="font-size:13px">{esc(domain)}</span>
      {f'<span style="font-size:11px;color:#64748b">{esc(hosting_type)}</span>' if hosting_type else ""}
    </div>
    <div class="section-label">Nameserver Records</div>'''
    for n in ns:
        html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="val mono">{esc(n)}</div></div>'
    if provider and not is_grid:
        html += f'<div class="card" style="margin-top:6px;border-color:#7c2d12"><div class="title" style="color:#fdba74">⚠ External Hosting</div><div class="preview">This domain uses {esc(provider)} nameservers. It is NOT hosted with 1-grid.</div></div>'
    return HTMLResponse(html)

# ── LOGS ──

@app.post("/views/logs/analyze")
async def logs_analyze(content: str = Form(...)):
    try:
        raw_lines = content.split("\n")
        lines = raw_lines[:500]
        total = len(raw_lines)

        # ── Expanded pattern definitions ──
        categories = [
            ("error", "red", [
                (r"PHP\s+Fatal.*error", "php_fatal", "PHP Fatal Error"),
                (r"PHP\s+Parse.*error", "php_parse", "PHP Parse Error"),
                (r"PHP\s+Warning", "php_warn", "PHP Warning"),
                (r"PHP\s+Notice", "php_notice", "PHP Notice"),
                (r"PHP\s+Error", "php_error", "PHP Error"),
                (r"Uncaught\s+[A-Z]\w+Exception", "php_exception", "PHP Uncaught Exception"),
                (r"stack\s+trace", "php_stack", "PHP Stack Trace"),
                (r"call\s+to\s+undefined\s+(function|method)", "php_undef", "PHP Undefined Function/Method"),
                (r"Class\s+['\"]?\w+['\"]?\s+not\s+found", "php_class", "PHP Class Not Found"),
            ]),
            ("error", "red", [
                (r"(MySQL|MariaDB)\s+Error", "mysql_err", "MySQL/MariaDB Error"),
                (r"mysqli?::?connect.*failed", "mysql_connect", "MySQL Connection Failed"),
                (r"PDOException", "pdo_err", "PDO Exception"),
                (r"SQLSTATE|database\s+error|db\s+error", "sql_err", "SQL Error"),
                (r"Table\s+['\"]?\w+['\"]?\s+doesn't\s+exist", "sql_notable", "SQL Table Not Found"),
                (r"Duplicate\s+entry", "sql_dup", "SQL Duplicate Entry"),
                (r"Lock\s+wait\s+timeout|deadlock", "sql_lock", "SQL Lock/Deadlock"),
                (r"max_user_connections|too\s+many\s+connections", "sql_conn", "MySQL Too Many Connections"),
                (r"Got\s+error\s+\d+\s+from\s+storage\s+engine", "sql_storage", "MySQL Storage Engine Error"),
            ]),
            ("error", "red", [
                (r"\s+500\s+", "http_500", "HTTP 500"),
                (r"\s+502\s+", "http_502", "HTTP 502 Bad Gateway"),
                (r"\s+503\s+", "http_503", "HTTP 503 Service Unavailable"),
                (r"\s+504\s+", "http_504", "HTTP 504 Gateway Timeout"),
                (r"upstream\s+timed\s+out", "upstream_timeout", "Upstream Timeout"),
                (r"upstream\s+closed\s+connection", "upstream_closed", "Upstream Closed Connection"),
                (r"no\s+live\s+upstreams", "upstream_dead", "No Live Upstreams"),
                (r"(504|502)\s+gateway", "gateway_err", "Gateway Error"),
            ]),
            ("warning", "amber", [
                (r"\s+(401|403)\s+", "http_40x", "HTTP 401/403 Unauthorized"),
                (r"\s+404\s+", "http_404", "HTTP 404 Not Found"),
                (r"\s+429\s+", "http_429", "HTTP 429 Rate Limited"),
            ]),
            ("error", "red", [
                (r"out\s+of\s+memory", "oom", "Out of Memory (OOM)"),
                (r"memory\s+exhausted|memory\s+limit|Allowed\s+memory", "mem_exhaust", "Memory Limit Exhausted"),
                (r"disk\s+full|disk\s+quota|no\s+space\s+left", "disk_full", "Disk Full / Quota Exceeded"),
                (r"Unable\s+to\s+write|failed\s+to\s+open\s+stream", "write_fail", "File Write Failure"),
                (r"read.*failed|read-only|readonly", "read_fail", "File Read Failure"),
            ]),
            ("warning", "amber", [
                (r"(WordPress|wp_|WPDB|wp_error|WP_Error)", "wp_generic", "WordPress Reference"),
                (r"WordPress.*error|wp_error", "wp_error", "WordPress Error"),
                (r"database\s+error.*WordPress", "wp_db", "WordPress Database Error"),
            ]),
            ("error", "red", [
                (r"timed?\s*out|timeout", "timeout", "Timeout"),
                (r"connection\s+refused|connection\s+reset|connection\s+closed", "conn_refused", "Connection Refused/Reset"),
                (r"could\s+not\s+connect|cannot\s+connect|unable\s+to\s+connect", "conn_fail", "Connection Failure"),
                (r"Network\s+is\s+unreachable|no\s+route\s+to\s+host", "net_unreach", "Network Unreachable"),
                (r"Name\s+or\s+service\s+not\s+known|Temporary\s+failure\s+in\s+name\s+resolution", "dns_fail", "DNS Resolution Failure"),
            ]),
            ("warning", "amber", [
                (r"SSL|TLS|certificate", "ssl_ref", "SSL/TLS Reference"),
                (r"certificate\s+(expired|has\s+expired)", "ssl_exp", "SSL Certificate Expired"),
                (r"certificate\s+verify\s+failed", "ssl_verify", "SSL Verify Failed"),
                (r"peer\s+did\s+not\s+return\s+a\s+certificate", "ssl_nopeer", "SSL No Peer Cert"),
                (r"permission\s+denied|cannot\s+open|not\s+permitted", "perm_denied", "Permission Denied"),
            ]),
            ("error", "red", [
                (r"Segmentation\s+fault|segfault|SIGSEGV", "segfault", "Segmentation Fault (SIGSEGV)"),
                (r"Bus\s+error|SIGBUS", "bus_error", "Bus Error"),
                (r"killed|SIGKILL|SIGTERM", "sigkill", "Process Killed"),
                (r"core\s+dumped", "core_dump", "Core Dump"),
            ]),
            ("info", "blue", [
                (r"WARNING|WARN\s", "warn_log", "General Warnings"),
                (r"ERROR|ERR\s|CRITICAL|CRIT\s|ALERT|EMERG", "err_log", "General Errors"),
                (r"NOTICE|NOTE", "notice_log", "General Notices"),
                (r"INFO", "info_log", "General Info Messages"),
            ]),
            ("error", "red", [
                (r"\s\*\*\s+\S+@\S+.*user\s+unknown", "exim_user_unknown", "Exim: User Unknown"),
                (r"\s\*\*\s+\S+@\S+.*Unrouteable\s+address", "exim_unrouteable", "Exim: Unrouteable Address"),
                (r"\s\*\*\s+\S+@\S+.*Mailbox\s+is\s+full|over\s+quota", "exim_quota", "Exim: Mailbox Full/Over Quota"),
                (r"\s\*\*\s+\S+@\S+.*550\s+Relay\s+not\s+permitted", "exim_relay", "Exim: Relay Not Permitted"),
                (r"\s\*\*\s+\S+@\S+.*DKIM\s+verification\s+failed", "exim_dkim", "Exim: DKIM Verification Failed"),
                (r"rejected\s+RCPT.*blacklist", "exim_blacklisted", "Exim: Blacklisted RBL Match"),
                (r"\s==\s+\S+@\S+.*defer", "exim_deferred", "Exim: Mail Deferred"),
                (r"\s\*\*\s+\S+@\S+.*reject_spam", "exim_spam", "Exim: Message Rejected as Spam"),
                (r"\s\*\*\s+\S+@\S+.*timeout", "exim_timeout", "Exim: SMTP Timeout"),
                (r"\s\*\*\s+\S+@\S+.*421\s+Temporary", "exim_tempfail", "Exim: Temporary DNS/Failure"),
            ]),
            ("warning", "amber", [
                (r"exim|dovecot|courier|postfix", "mta_ref", "Mail Server (MTA)"),
                (r"spam|virus|malware", "security", "Security Threat Reference"),
                (r"mod_security|ModSecurity|rule\s+denied", "modsec", "ModSecurity Blocked"),
                (r"brute.?force|login\s+fail|auth\s+fail|authentication\s+failure", "auth_fail", "Authentication Failure"),
            ]),
        ]

        findings = []
        all_hits = {}
        line_info = []

        for severity, color, patterns in categories:
            for pattern, ftype, label in patterns:
                hits = []
                for idx, line in enumerate(lines):
                    if re.search(pattern, line, re.I):
                        hits.append((idx + 1, line))
                if hits:
                    findings.append({
                        "type": ftype,
                        "label": label,
                        "severity": severity,
                        "color": color,
                        "count": len(hits),
                        "samples": hits[:4],
                        "lines": [h[0] for h in hits],
                    })
                    all_hits[ftype] = hits

        # Count total hits for summary
        error_count = sum(f["count"] for f in findings if f["severity"] == "error")
        warn_count = sum(f["count"] for f in findings if f["severity"] == "warning")
        info_count = sum(f["count"] for f in findings if f["severity"] == "info")

    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')

    if not findings:
        return HTMLResponse(f'<div class="card"><div class="title" style="color:#4ade80">✅ Clean</div><div class="meta">{total} lines scanned — no errors or warnings detected</div></div>')

    # ── Build output ──
    html = ""
    # Summary header
    html += f'<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">'
    html += f'<div class="card" style="flex:1;min-width:120px"><div class="title" style="color:#f87171">🔴 {error_count}</div><div class="meta">Errors</div></div>'
    html += f'<div class="card" style="flex:1;min-width:120px"><div class="title" style="color:#facc15">🟡 {warn_count}</div><div class="meta">Warnings</div></div>'
    html += f'<div class="card" style="flex:1;min-width:120px"><div class="title" style="color:#60a5fa">🔵 {info_count}</div><div class="meta">Info</div></div>'
    html += f'<div class="card" style="flex:1;min-width:120px"><div class="title">{total}</div><div class="meta">Lines scanned</div></div>'
    html += '</div>'

    # Top categories
    cats = {}
    for f in findings:
        base = f["label"].split(" ")[0] if f["label"] else "Other"
        cats[base] = cats.get(base, 0) + f["count"]
    top_cats = sorted(cats.items(), key=lambda x: -x[1])[:5]
    if top_cats:
        html += '<div class="card" style="margin-bottom:8px"><div class="title">📊 Top Categories</div><div class="meta" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">'
        for name, count in top_cats:
            html += f'<span style="background:#1e293b;padding:2px 8px;border-radius:4px;font-size:11px">{esc(name)}: {count}</span>'
        html += '</div></div>'

    # Recommendation engine
    recs = []
    seen_types = {f["type"] for f in findings}
    if "conn_refused" in seen_types or "conn_fail" in seen_types or "net_unreach" in seen_types:
        recs.append("🔌 Check firewall rules and verify services are running on the expected ports")
    if "dns_fail" in seen_types:
        recs.append("🌐 DNS resolution failing — check nameserver config or try flushing DNS cache")
    if "disk_full" in seen_types:
        recs.append("💾 Disk full — run 'df -h', delete old logs, temp files, or unused backups")
    if "oom" in seen_types or "mem_exhaust" in seen_types:
        recs.append("🧠 Out of memory — increase PHP memory_limit, add swap, or upgrade RAM")
    if "ssl_exp" in seen_types or "ssl_verify" in seen_types:
        recs.append("🔒 SSL certificate issue — renew cert and verify chain validity")
    if "php_fatal" in seen_types or "php_exception" in seen_types:
        recs.append("🐘 PHP error — check recent code deploys, enable WP_DEBUG for more detail")
    if "sql_lock" in seen_types or "sql_conn" in seen_types:
        recs.append("🗄️ Database contention — check slow queries, increase max_connections, or optimize tables")
    if "http_5xx" in seen_types or "gateway_err" in seen_types:
        recs.append("🌍 HTTP 5xx errors — check application logs, restart PHP-FPM, verify upstream services")
    if "timeout" in seen_types:
        recs.append("⏱️ Timeouts — increase execution time limits, optimize slow queries, check network latency")
    if "auth_fail" in seen_types or "http_40x" in seen_types:
        recs.append("🔐 Authentication failures — check credentials, reset passwords, review access logs")
    if "perm_denied" in seen_types:
        recs.append("🔒 Permission denied — check file ownership and permissions (chown/chmod)")
    # Mail-specific recs
    if "exim_user_unknown" in seen_types or "exim_unrouteable" in seen_types:
        recs.append("📧 Unknown recipients — check if email addresses exist or are misspelled, review aliases in /etc/aliases")
    if "exim_quota" in seen_types:
        recs.append("📦 Mailbox full — user needs to delete emails or increase quota (check 'mailbox_size_limit')")
    if "exim_relay" in seen_types:
        recs.append("🚫 Relay not permitted — the receiving server rejected your mail. Check SPF/DKIM and that you're authorized to send for that domain")
    if "exim_dkim" in seen_types:
        recs.append("✍️ DKIM failed — check DNS for valid DKIM record, verify selector matches your mail server")
    if "exim_blacklisted" in seen_types:
        recs.append("🛡️ Server blacklisted at zen.spamhaus.org — check http://www.spamhaus.org/query/ip/ for delisting instructions")
    if "exim_deferred" in seen_types:
        recs.append("⏳ Mail deferred — temporary delivery failure. Check DNS resolution, recipient server availability, and retry queue")
    if "exim_tempfail" in seen_types:
        recs.append("🌐 Temporary DNS lookup failure — check DNS resolution on the server, verify nameservers are responding")
    if recs:
        html += '<div class="card" style="margin-bottom:8px;border-color:#2563eb">'
        html += '<div class="title" style="color:#60a5fa">💡 Recommendations</div>'
        for r in recs[:12]:
            html += f'<div style="font-size:12px;color:#94a3b8;margin-top:4px">{r}</div>'
        html += '</div>'

    # Per-pattern detail
    for f in findings:
        bc = "#7f1d1d" if f["color"] == "red" else "#7c3a1d" if f["color"] == "amber" else "#1e3a5f"
        sev_icon = {"error":"🔴","warning":"🟡","info":"🔵"}.get(f["severity"], "⚪")
        html += f'<div class="card" style="margin-bottom:4px;border-color:{bc}">'
        html += f'<div class="title">{sev_icon} {f["label"]} <span style="font-weight:400;color:#64748b">({f["count"]}×)</span></div>'
        span = min(2, len(f["samples"]))
        for lineno, s in f["samples"][:span]:
            html += f'<div style="display:flex;gap:6px;margin-top:3px;font-family:monospace;font-size:11px">'
            html += f'<span style="color:#475569;white-space:nowrap">L{lineno}</span>'
            html += f'<span style="color:#94a3b8;word-break:break-all">{esc(str(s)[:250])}</span>'
            html += '</div>'
        if f["count"] > span:
            html += f'<div style="font-size:10px;color:#475569;margin-top:2px">… and {f["count"] - span} more on lines {", ".join(str(l) for l in f["lines"][span:span+5])}{"…" if len(f["lines"]) > span+5 else ""}</div>'
        html += '</div>'

    return HTMLResponse(html)

# ── DNS ──

@app.post("/views/dns/lookup")
async def dns_lookup(domain: str = Form(...), type: str = Form("ANY")):
    try:
        d = run_dig(domain, type)
        if not d.get("success"):
            return HTMLResponse(f'<div class="empty">Lookup failed: {esc(d.get("error",""))}</div>')
        try:
            results = json.loads(d.get("stdout","{}")) if isinstance(d.get("stdout"), str) else d.get("stdout",[])
        except:
            results = d.get("stdout", str(d))
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')

    html = f'<div class="card" style="margin-bottom:6px"><div class="title">🔎 {esc(domain)} {esc(type)}</div></div>'
    if isinstance(results, list):
        for r in results:
            html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="val mono">{esc(str(r))}</div></div>'
    elif isinstance(results, dict):
        for k, v in results.items():
            vals = ", ".join(v) if isinstance(v, list) else str(v)
            html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="meta">{esc(k)}</div><div class="val mono">{esc(vals)}</div></div>'
    else:
        html += f'<div class="card" style="padding:6px 10px"><div class="val mono">{esc(str(results))}</div></div>'
    return HTMLResponse(html)

# ── WHOIS ──

@app.post("/views/whois/lookup")
async def whois_lookup_view(domain: str = Form(...)):
    try:
        data = whois_lookup(domain)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')
    html = f'<div class="card" style="margin-bottom:6px"><div class="title">📇 {esc(domain)}</div></div><div class="details-grid">'
    for k in ["registrar","expiry","status"]:
        v = data.get(k)
        if v:
            html += f'<span class="k">{k.title()}</span><span class="v">{esc(str(v))}</span>'
    html += '</div>'
    raw = data.get("raw","")
    if raw:
        html += f'<div class="card" style="margin-top:6px"><div class="title">Raw WHOIS</div><div class="preview mono" style="font-family:monospace;font-size:10px;max-height:200px;overflow-y:auto">{esc(raw[:500])}</div></div>'
    return HTMLResponse(html)

# ── PORTS ──

@app.post("/views/ports/scan")
async def ports_scan(domain: str = Form(...)):
    try:
        open_ports = port_scan(domain)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')
    html = f'<div class="card" style="margin-bottom:6px"><div class="title">🔌 Port Scan: {esc(domain)}</div><div class="meta">{len(open_ports)} ports open</div></div>'
    if open_ports:
        for p, n in open_ports:
            html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="title">{esc(n)} <span style="font-weight:400;color:#64748b">port {p}</span></div></div>'
    else:
        html += '<div class="empty">No common ports open (or host unreachable)</div>'
    return HTMLResponse(html)

# ── HTTP CHECK ──

@app.post("/views/httpcheck/check")
async def httpcheck_check(domain: str = Form(...)):
    try:
        http_s, https_s, ssl_d = http_check(domain)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')
    html = f'<div class="card" style="margin-bottom:6px"><div class="title">🌍 {esc(domain)}</div></div><div class="details-grid">'
    if http_s:
        code = http_s.get("status_code","?")
        cls = "red" if code >= 400 else "amber" if code >= 300 else "green"
        html += f'<span class="k">HTTP</span><span class="v {cls}">{code}</span>'
    if https_s:
        code = https_s.get("status_code","?")
        cls = "red" if code >= 400 else "amber" if code >= 300 else "green"
        html += f'<span class="k">HTTPS</span><span class="v {cls}">{code}</span>'
    if ssl_d is not None:
        cls = "red" if ssl_d < 0 else "red" if ssl_d < 14 else "amber" if ssl_d < 60 else "green"
        txt = "EXPIRED" if ssl_d < 0 else f"{ssl_d} days"
        html += f'<span class="k">SSL</span><span class="v {cls}">{txt}</span>'
    html += '</div>'
    if http_s and http_s.get("error"):
        html += f'<div class="card" style="margin-top:6px;border-color:#7f1d1d"><div class="preview" style="color:#f87171">HTTP error: {esc(http_s["error"])}</div></div>'
    return HTMLResponse(html)

# ── SUBDOMAINS ──

@app.post("/views/subdomains/enum")
async def subdomains_enum(domain: str = Form(...)):
    try:
        subs = enum_subdomains(domain)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')
    html = f'<div class="card" style="margin-bottom:6px"><div class="title">🗂️ Subdomains: {esc(domain)}</div><div class="meta">{len(subs)} found</div></div>'
    if subs:
        for sd in subs:
            info = ", ".join(sd.get("ips",[])) if sd.get("ips") else ("CNAME → "+sd.get("cname","") if sd.get("cname") else "")
            html += f'<div class="card" style="padding:5px 10px;margin-bottom:2px"><div class="val mono">{esc(sd.get("subdomain",""))} → {esc(info)}</div></div>'
    else:
        html += '<div class="empty">No common subdomains found</div>'
    return HTMLResponse(html)

# ── BLOCKLISTS ──

@app.post("/views/blocklists/check")
async def blocklists_check(ip: str = Form(...)):
    try:
        bl = check_blocklists(ip)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')
    html = f'<div class="card" style="margin-bottom:6px"><div class="title">🛡️ IP: {esc(ip)}</div></div>'
    if bl:
        for b in bl:
            cls = "red" if b.get("listed") else "green"
            html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="title">{esc(b.get("list",""))}</div><div class="val {cls}">{"LISTED ⚠" if b.get("listed") else "Clean ✓"}</div></div>'
    return HTMLResponse(html)

# ── CONVERSATIONS ──

@app.post("/views/conversations/search")
async def conversations_search(q: str = Form("")):
    convs = warehouse.get_conversations(200)
    if q:
        ql = q.lower()
        convs = [c for c in convs if ql in json.dumps(c).lower()]

    # Group related messages into conversations
    def extract_domain(c):
        d = (c.get("metadata") or {}).get("domain", "")
        if not d:
            txt = c.get("content", "")
            # Prefer co.za domains or common TLDs, skip false matches like acme.sh
            m = re.search(r"([\w-]+\.(?:co\.za|com|org|net|io|dev|app|info|biz|za|cloud|online|site))\b", txt)
            if not m:
                m = re.search(r"([\w-]+\.[\w.]{2,})", txt)
            if m:
                d = m.group(1)
        return d.lower().rstrip(".")

    def parse_ts(ts):
        try:
            from datetime import datetime
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except:
            return None

    # Build groups: same domain + timestamps within 1 hour
    groups = []
    used = set()
    for i, c in enumerate(convs):
        if i in used:
            continue
        domain = extract_domain(c)
        ts_c = parse_ts(c.get("timestamp", ""))
        group = {
            "id": c.get("id", ""),
            "domain": domain,
            "source": c.get("source", "") or c.get("role", "unknown"),
            "timestamp": c.get("timestamp", ""),
            "messages": [{
                "role": c.get("role", "unknown"),
                "content": c.get("content", ""),
                "thoughts": c.get("thoughts", []),
                "commands": c.get("commands", []),
                "timestamp": c.get("timestamp", ""),
            }]
        }
        used.add(i)
        # Look for related messages (same domain, within 1 hour)
        for j, c2 in enumerate(convs):
            if j in used:
                continue
            domain2 = extract_domain(c2)
            ts_c2 = parse_ts(c2.get("timestamp", ""))
            if domain and domain2 and domain == domain2 and ts_c and ts_c2:
                diff = abs((ts_c - ts_c2).total_seconds())
                if diff < 3600:
                    group["messages"].append({
                        "role": c2.get("role", "unknown"),
                        "content": c2.get("content", ""),
                        "thoughts": c2.get("thoughts", []),
                        "commands": c2.get("commands", []),
                        "timestamp": c2.get("timestamp", ""),
                    })
                    used.add(j)
        # Sort messages by timestamp
        group["messages"].sort(key=lambda m: m.get("timestamp", ""))
        groups.append(group)

    if not groups:
        return HTMLResponse('<div class="empty">No conversations found</div>')

    # Sort groups by latest message timestamp
    groups.sort(key=lambda g: g.get("timestamp", ""), reverse=True)

    html = ""
    for g in groups:
        msgs = g.get("messages", [])
        first = esc(msgs[0].get("content", "")[:120]) if msgs else ""
        domain_tag = ""
        if g.get("domain"):
            domain_tag = f'<span style="background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:12px;font-size:10px;margin-left:6px">{esc(g["domain"])}</span>'
        roles = ", ".join(set(m.get("role","") for m in msgs))
        html += f"<div class='card clickable' onclick='showConvDetail(this,{esc_js(json.dumps(g))})'>"
        html += f'<div class="title">💬 {esc(g.get("source","conversation"))}{domain_tag}</div>'
        html += f'<div class="meta"><span>📅 {esc(g.get("timestamp",""))}</span><span>💬 {len(msgs)} messages</span><span>👤 {esc(roles)}</span></div>'
        html += f'<div class="preview">{first}</div></div>'
    return HTMLResponse(html)

# ── ISSUES ──

@app.post("/views/issues/search")
async def issues_search(q: str = Form("")):
    issues_data = warehouse.search_issues(q, 20)
    if not issues_data:
        return HTMLResponse('<div class="empty">No issues found</div>')
    html = ""
    for iss in issues_data:
        status_cls = "green" if iss.get("status") == "resolved" else "red"
        html += f'''<div class="card clickable" onclick="showIssueDetail(this,{esc(json.dumps(iss)).replace(chr(39),"&#39;")})">
          <div class="title">{esc(iss.get("domain",""))} <span style="font-weight:400;font-size:11px;color:#64748b">#{esc(iss.get("ticket_ref","?"))}</span></div>
          <div class="meta"><span>📅 {esc(iss.get("created_at",""))}</span><span>🏷️ {esc(iss.get("issue_type",""))}</span><span>📌 <span class="{status_cls}">{esc(iss.get("status",""))}</span></span></div>
          <div class="preview">{esc((iss.get("issue_summary","") or "")[:200])}</div>
        </div>'''
    return HTMLResponse(html)

# ── PATTERNS ──

@app.get("/views/patterns/list")
async def patterns_list():
    servers_data = warehouse.tickets_by_server()
    if not servers_data:
        return HTMLResponse('<div class="empty">No patterns found</div>')
    html = ""
    for s in servers_data:
        html += f'''<div class="card clickable" style="margin-bottom:6px" onclick="htmx.ajax('POST','/views/tickets/search',{{values:{{q:"{esc(s.get("server_ip",""))}"}},target:"#panel",swap:"innerHTML"}})">
          <div class="title">🖥️ {esc(s.get("server_ip","Unknown"))} {f"({esc(s.get('ptr',''))})" if s.get("ptr") else ""}</div>
          <div class="meta"><span>📋 {s.get("count",0)} tickets</span><span>🏷️ {esc(s.get("categories",""))}</span></div>
          <div class="meta"><span>🌐 {esc(s.get("domains",""))}</span></div>
          <div class="meta"><span>📌 {esc(s.get("sub_categories",""))}</span></div>
          {f'<div class="meta"><span>{esc(s["outcomes"])}</span></div>' if s.get("outcomes") else ""}
        </div>'''
    return HTMLResponse(html)

# ── SERVERS ──

@app.post("/views/servers/filter")
async def servers_filter(q: str = Form("")):
    servers_data = warehouse.servers_enriched()
    if q:
        ql = q.lower()
        servers_data = [s for s in servers_data if ql in json.dumps(s).lower()]
    if not servers_data:
        return HTMLResponse('<div class="empty">No servers found</div>')
    html = ""
    for s in servers_data:
        ip = esc(s.get("server_ip",""))
        ptr = esc(s.get("ptr",""))
        hostname = esc(s.get("hostname",""))
        ht = esc(s.get("hosting_type",""))
        ptr_part = f" ({ptr})" if s.get("ptr") else ""
        hn_part = f'<span>{hostname}</span>' if s.get("hostname") else ""
        ht_part = f'<span>{ht}</span>' if s.get("hosting_type") else ""
        html += f'<div class="card" style="margin-bottom:4px">'
        html += f'<div class="title">🖥️ {ip}{ptr_part}</div>'
        html += f'<div class="meta">{hn_part}<span>📋 {s.get("ticket_count",0)} tickets</span>{ht_part}</div>'
        if s.get("domains"): html += f'<div class="preview">🌐 {esc(s["domains"])}</div>'
        if s.get("categories"): html += f'<div class="preview">🏷️ {esc(s["categories"])}</div>'
        if s.get("outcomes"): html += f'<div class="preview">📌 {esc(s["outcomes"])}</div>'
        if s.get("known_issues"): html += f'<div class="preview" style="color:#f87171">⚠️ {esc(s["known_issues"])}</div>'
        html += '</div>'
    return HTMLResponse(html)

# ── QUICK REF ──

@app.post("/views/quickref/filter")
async def quickref_filter(q: str = Form("")):
    refs = warehouse.get_quick_ref()
    groups = {}
    for r in refs:
        cat = r.get("category", "General")
        groups.setdefault(cat, []).append(r)
    ql = q.lower() if q else ""
    html = ""
    for cat in sorted(groups.keys()):
        items = groups[cat]
        if ql:
            items = [r for r in items if ql in (r.get("key_name","") + cat + (r.get("value","") or "")).lower()]
        if not items:
            continue
        html += f'<div style="margin-bottom:4px"><div style="font-size:11px;color:#94a3b8;font-weight:500;margin:8px 0 3px 4px">{esc(cat)}</div>'
        for r in items:
            val = esc((r.get("value","") or "")[:300])
            name = esc(r.get("key_name",""))
            html += f'<div class="card clickable" style="margin-bottom:3px" onclick="navigator.clipboard.writeText({esc(json.dumps(r.get("value","")))});toast(\'Copied!\')"><div class="title">{name}</div><div class="preview" style="font-family:monospace;font-size:11px;color:#a5b4fc">{val}</div></div>'
        html += '</div>'
    if not html:
        return HTMLResponse('<div class="empty">No matching references</div>')
    return HTMLResponse(html)

# ── STATUS ──

@app.get("/views/status/data")
async def status_data():
    ollama_ok = False
    try:
        import httpx
        r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3)
        ollama_ok = r.status_code == 200
    except: pass
    try:
        wc = warehouse.counts()
        db_info = f"MongoDB: {wc.get('tickets','?')} tickets, {wc.get('issues','?')} issues, {wc.get('quickrefs','?')} refs"
    except:
        db_info = "MongoDB: check connection"
    try:
        kb_count = len(retrieve_context_structured("test", 10))
    except:
        kb_count = "?"

    html = f'''
    <div class="card"><div class="title">📊 System Status</div></div>
    <div class="card" style="margin-top:4px"><div class="title">Server</div><div class="meta"><span>Status: ok</span><span>Model: {esc(_llm_name())}</span></div></div>
    <div class="card" style="margin-top:4px"><div class="title">Ollama</div><div class="meta"><span>Status: {"connected" if ollama_ok else "disconnected"}</span></div></div>
    <div class="card" style="margin-top:4px"><div class="title">Database</div><div class="meta"><span>{esc(db_info)}</span></div></div>
    <div class="card" style="margin-top:4px"><div class="title">KB Articles</div><div class="meta"><span>{kb_count} articles indexed</span></div></div>
    <div class="card" style="margin-top:4px"><div class="title">Endpoints</div><div class="meta"><span>20+ tool/data endpoints</span><span>HTMX-powered UI</span></div></div>'''
    return HTMLResponse(html)

# ── CHAT MESSAGE DISPLAY ──

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
