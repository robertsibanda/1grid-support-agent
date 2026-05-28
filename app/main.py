import json
import logging
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from app.config import settings
from app.agent.pipeline import SupportPipeline
from app.rag.chroma_client import ChromaService
from app.rag.kb_ingest import ingest_all_kb, ingest_from_warehouse
from app.rag.retriever import retrieve_context_structured
from app.warehouse.mongo_warehouse import MongoWarehouse
from app.htmx_views import router as htmx_router, init_wh as htmx_init_wh
from app.zonewalk.runner import run_zonewalk, run_dig, run_whois
from app.zonewalk.runner import (
    run_zonewalk_full, parse_email_headers, check_propagation,
    whois_lookup, port_scan, check_blocklists, enum_subdomains,
    http_check, Resolver, GRID_NS_PATTERNS, COMPETITORS, COMMON_PORTS
)

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)

pipeline = SupportPipeline()
chroma = ChromaService()
warehouse = MongoWarehouse(uri=settings.mongo_uri, db_name=settings.mongo_db_name)
htmx_init_wh(warehouse)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting 1-grid AI Support Agent (model: {settings.ollama_model})")
    try:
        from app.rag.kb_ingest import ingest_all_kb
        ing = ingest_all_kb()
        logger.info(f"KB auto-ingest: {ing['ingested']} new, {ing['total']} total")
    except Exception as e:
        logger.warning(f"KB auto-ingest skipped: {e}")

    try:
        counts = warehouse.import_from_sqlite(settings.warehouse_db)
        conv_count = warehouse.import_conversations(settings.conversations_jsonl)
        logger.info(f"MongoDB warehouse loaded: {sum(counts.values())} docs from SQLite, {conv_count} conversations")
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

app.include_router(htmx_router)

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

# --- Endpoints ---

@app.get("/health")
async def health():
    return {"status": "ok", "model": settings.ollama_model}

@app.get("/health/ollama")
async def health_ollama():
    try:
        import httpx
        r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3)
        if r.status_code == 200:
            return {"status": "ok", "model": settings.ollama_model}
        return {"status": "disconnected", "model": None}
    except:
        return {"status": "disconnected", "model": None}

# --- New Structured Endpoints ---

@app.post("/zonewalk/check")
async def zonewalk_check(req: ZonewalkCheckRequest):
    """Run full zonewalk, return structured JSON."""
    result = run_zonewalk_full(
        req.domain,
        deep=req.deep,
        ports=req.ports,
        reputation=req.reputation,
    )
    return result.to_dict()

@app.post("/mail/headers")
async def mail_headers_analyze(req: HeadersRequest):
    """Parse and analyze raw email headers."""
    analysis = parse_email_headers(req.headers)
    return analysis

@app.post("/propagation")
async def propagation_check(domain: str = Body(...)):
    """Check DNS propagation across global resolvers."""
    res = Resolver()
    a_records = res.a(domain)
    if a_records:
        return {"domain": domain, "propagation": check_propagation(domain, a_records), "a_records": a_records}
    return {"domain": domain, "propagation": [], "a_records": []}

@app.post("/nameservers")
async def nameservers_check(domain: str = Body(...)):
    """Check nameservers and detect hosting provider."""
    res = Resolver()
    ns = res.ns(domain)
    provider = "Unknown"
    is_grid = False
    hosting_type = ""
    for ns_host in ns:
        for pattern, htype in GRID_NS_PATTERNS.items():
            if pattern in ns_host.lower():
                provider = "1-grid"
                is_grid = True
                hosting_type = htype
                break
        if is_grid: break
    if not is_grid:
        for pattern, name in COMPETITORS:
            if any(pattern in n.lower() for n in ns):
                provider = name; break
    return {"domain": domain, "nameservers": ns, "is_grid": is_grid, "provider": provider, "hosting_type": hosting_type}

@app.post("/log/analyze")
async def log_analyze(req: LogRequest):
    """Analyze log text for common patterns."""
    text = req.content
    findings = []
    lines = text.split("\n")[:200]
    # PHP errors
    phperrs = [l for l in lines if re.search(r"PHP\s+(Fatal|Warning|Notice|Parse|Error)", l, re.I)]
    if phperrs: findings.append({"type": "PHP_Errors", "count": len(phperrs), "samples": phperrs[:5]})
    # MySQL
    mysqlerrs = [l for l in lines if re.search(r"(MySQL|MariaDB|mysqli|PDOException|SQLSTATE)", l, re.I)]
    if mysqlerrs: findings.append({"type": "MySQL_Errors", "count": len(mysqlerrs), "samples": mysqlerrs[:5]})
    # 40x/50x
    http4xx = [l for l in lines if re.search(r"\s(401|403|404)\s", l)]
    if http4xx: findings.append({"type": "HTTP_4xx", "count": len(http4xx), "samples": http4xx[:3]})
    http5xx = [l for l in lines if re.search(r"\s(500|502|503|504)\s", l)]
    if http5xx: findings.append({"type": "HTTP_5xx", "count": len(http5xx), "samples": http5xx[:3]})
    # WordPress
    wperrs = [l for l in lines if re.search(r"(WordPress|wp_|WPDB|wp_error)", l, re.I)]
    if wperrs: findings.append({"type": "WordPress", "count": len(wperrs), "samples": wperrs[:5]})
    # Connection timeouts
    toerrs = [l for l in lines if re.search(r"(timeout|timed\s*out|connection\s+refused)", l, re.I)]
    if toerrs: findings.append({"type": "Connection_Timeout", "count": len(toerrs), "samples": toerrs[:3]})
    # Disk/Memory
    reserrs = [l for l in lines if re.search(r"(disk\s+full|out\s+of\s+memory|memory\s+exhausted|disk\s+quota)", l, re.I)]
    if reserrs: findings.append({"type": "Resource_Limit", "count": len(reserrs), "samples": reserrs[:3]})
    # Permission denied
    permerrs = [l for l in lines if re.search(r"(permission\s+denied|cannot\s+open|failed\s+to\s+open)", l, re.I)]
    if permerrs: findings.append({"type": "Permission_Denied", "count": len(permerrs), "samples": permerrs[:3]})
    return {"total_lines": len(text.split("\n")), "findings": findings}

@app.post("/tools/dig")
async def tools_dig(domain: str = Body(...), query_type: str = Body("ANY")):
    """DNS lookup tool."""
    return run_dig(domain, query_type)

@app.post("/tools/whois")
async def tools_whois(domain: str = Body(...)):
    """WHOIS lookup tool."""
    data = whois_lookup(domain)
    return {"domain": domain, "registrar": data.get("registrar",""), "expiry": data.get("expiry",""), "status": data.get("status",""), "raw": data.get("raw","")[:500]}

@app.post("/tools/portscan")
async def tools_portscan(domain: str = Body(...)):
    """Port scan tool."""
    open_ports = port_scan(domain)
    return {"domain": domain, "open_ports": [{"port": p, "service": n} for p, n in open_ports]}

@app.post("/tools/subdomains")
async def tools_subdomains(domain: str = Body(...)):
    """Subdomain enumeration tool."""
    subs = enum_subdomains(domain)
    return {"domain": domain, "subdomains": subs}

@app.get("/tools/blocklists")
async def tools_blocklists(ip: str):
    """Check IP against DNS blocklists."""
    return {"ip": ip, "blocklists": check_blocklists(ip)}

@app.post("/tools/httpcheck")
async def tools_httpcheck(domain: str = Body(...)):
    """HTTP/HTTPS/SSL check."""
    http_s, https_s, ssl_d = http_check(domain)
    return {"domain": domain, "http": http_s, "https": https_s, "ssl_days": ssl_d}

# ---

@app.post("/ticket")
async def process_ticket(req: TicketRequest):
    result = await pipeline.process_ticket(
        domain=req.domain,
        issue=req.issue,
        ticket_id=req.ticket_id,
        customer_email=req.customer_email
    )
    return result

@app.post("/diagnose")
async def diagnose(req: DiagnoseRequest):
    result = await pipeline.quick_diagnose(domain=req.domain, issue=req.issue)
    return result

@app.post("/kb/query")
async def query_kb(req: KBQueryRequest):
    from app.rag.retriever import retrieve_context_structured
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
    result = run_zonewalk(req.domain)
    return result

@app.post("/dig")
async def dig(domain: str, query_type: str = "ANY"):
    return run_dig(domain, query_type)

@app.post("/whois")
async def whois(domain: str):
    return run_whois(domain)

@app.get("/conversations")
async def conversations(limit: int = 50):
    """Read conversation history from NoSQL warehouse."""
    convs = warehouse.get_conversations(limit)
    return {"conversations": convs, "total": len(warehouse.conversations.all())}

@app.get("/warehouse/counts")
async def warehouse_counts():
    """Show document counts per collection in the NoSQL warehouse."""
    return warehouse.counts()

@app.get("/issues")
async def issues(q: str = "", limit: int = 20):
    """Search issues table (NoSQL warehouse)."""
    return {"issues": warehouse.search_issues(q, limit)}

@app.get("/servers/enriched")
async def servers_enriched():
    """Merge servers table with unique IPs from tickets including ticket counts (NoSQL warehouse)."""
    return {"servers": warehouse.servers_enriched(), "total": len(warehouse.servers_enriched())}

@app.get("/tickets")
async def tickets(q: str = "", limit: int = 20):
    """Search tickets (NoSQL warehouse)."""
    return {"tickets": warehouse.search_tickets(q, limit)}

@app.get("/tickets/by-server")
async def tickets_by_server():
    """Group tickets by server IP (NoSQL warehouse)."""
    return {"servers": warehouse.tickets_by_server()}

@app.get("/kb/search")
async def kb_search(q: str = "", n: int = 10):
    """Search KB articles with content preview."""
    from app.rag.retriever import retrieve_context_structured
    if not q:
        return {"articles": []}
    results = retrieve_context_structured(q, n)
    articles = []
    for r in results:
        articles.append({
            "title": r["metadata"].get("title", ""),
            "category": r["metadata"].get("category", ""),
            "content": r["content"][:2000],
            "distance": r.get("distance", 0),
        })
    return {"articles": articles}

@app.get("/kb/detail")
async def kb_detail(title: str = ""):
    """Get full KB article by title."""
    from app.rag.retriever import retrieve_context_structured
    if not title:
        return {"error": "title required"}
    results = retrieve_context_structured(title, 20)
    for r in results:
        if r["metadata"].get("title", "").lower() == title.lower():
            return {"article": {
                "title": r["metadata"].get("title", ""),
                "category": r["metadata"].get("category", ""),
                "content": r["content"],
            }}
    return {"error": "not found"}

@app.get("/quickref/by-category")
async def quickref_by_category():
    """Get quick references grouped by category."""
    refs = warehouse.get_quick_ref()
    groups = {}
    for r in refs:
        cat = r.get("category", "General")
        groups.setdefault(cat, []).append(r)
    return {"categories": groups}

@app.get("/")
async def index():
    with open("app/templates/index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/chat")
async def chat(req: ChatRequest):
    msg = req.message.strip()
    if not msg:
        return {"response": "Please enter a message."}

    # --- Commands ---
    if msg == "/help":
        return {"response": (
            "Commands:\n"
            "  <domain.tld> <issue>     Diagnose a domain issue\n"
            "  /history <domain>        Lookup domain history\n"
            "  /kb <query>              Search KB articles\n"
            "  /canned <topic>          Find canned responses\n"
            "  /quickref <query>        Lookup quick reference\n"
            "  /servers                 List known servers\n"
            "  /client <query>          Lookup client info\n"
            "  /status                  Show system status\n"
            "  /help                    Show this message"
        )}

    if msg == "/status":
        ollama_ok = False
        try:
            import httpx
            r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3)
            ollama_ok = r.status_code == 200
        except:
            pass
        kb_count = len(retrieve_context_structured("test", 10)) if retrieve_context_structured("test", 10) else 0
        try:
            wc = warehouse.counts()
            db_info = f"MongoDB 1grid: {wc['tickets']} tickets, {wc['issues']} issues, {wc['quickrefs']} refs"
        except:
            db_info = "MongoDB: check connection"
        return {"response": (
            f"Ollama: {'connected' if ollama_ok else 'disconnected'}\n"
            f"Model:  {settings.ollama_model}\n"
            f"DB:     {db_info}\n"
            f"KB:     {kb_count} articles indexed"
        )}

    if msg.startswith("/history "):
        domain = msg[9:].strip()
        issues = warehouse.search_issues(domain)
        if issues:
            lines = [f"History for {domain}:"]
            for i in issues:
                lines.append(f"  #{i['id']} [{i['status']}] {i['issue_type']} - {i.get('issue_summary','')[:200]}")
            return {"response": "\n".join(lines)}
        return {"response": f"No history for {domain}"}

    if msg.startswith("/kb "):
        query = msg[4:].strip()
        hits = retrieve_context_structured(query, 5)
        if hits:
            lines = [f"KB articles for '{query}':"]
            for h in hits:
                lines.append(f"  - {h['metadata'].get('title','')} (dist: {h.get('distance',0):.3f})")
            return {"response": "\n".join(lines)}
        return {"response": "No KB articles found."}

    if msg.startswith("/canned "):
        topic = msg[8:].strip()
        resp = warehouse.get_canned_response(topic)
        if resp:
            lines = []
            for r in resp:
                lines.append(f"[{r['title']}]")
                lines.append(f"{r['response_body'][:300]}...")
            return {"response": "\n".join(lines)}
        return {"response": f"No canned responses for '{topic}'"}

    if msg.startswith("/quickref "):
        query = msg[10:].strip()
        refs = warehouse.get_quick_ref(query)
        if refs:
            lines = [f"Quick refs for '{query}':"]
            for r in refs:
                lines.append(f"  [{r['category']}] {r['key_name']}: {r['value'][:200]}")
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

    # --- Domain issue diagnosis ---
    parts = msg.split(" ", 1)
    domain = parts[0].strip()
    issue = parts[1].strip() if len(parts) > 1 else "General inquiry"

    if not domain or "." not in domain:
        return {"response": "Usage: <domain.tld> <issue description>\ne.g. example.co.za not receiving email"}

    lines = []
    lines.append("=== Running zonewalk ===")
    z = run_zonewalk(domain)
    zw_text = z.get("stdout", "") or z.get("error", "Not available on this machine")
    lines.append(zw_text[:500])
    lines.append("")

    lines.append("=== Checking warehouse history ===")
    issues = warehouse.search_issues(domain)
    if issues:
        for i in issues[:5]:
            lines.append(f"  #{i['id']} [{i['status']}] {i['issue_type']} - {i.get('issue_summary','')[:200]}")
    else:
        lines.append("  No history found")
    lines.append("")

    lines.append("=== Searching KB ===")
    kb_hits = retrieve_context_structured(f"{domain} {issue}", n_results=4)
    if kb_hits:
        for h in kb_hits:
            lines.append(f"  - {h['metadata'].get('title','')}")
    else:
        lines.append("  No relevant articles")
    lines.append("")

    lines.append("=== Diagnosis ===")
    lines.append(f"Issue: {issue}")
    lines.append("")
    if issues:
        lines.append("Last resolved issue:")
        lines.append(f"  {issues[0].get('resolution','')[:300] or issues[0].get('issue_summary','')[:300]}")
        lines.append("")
        if issues[0].get('ticket_ref'):
            lines.append(f"  Ticket: #{issues[0]['ticket_ref']}")

    return {"response": "\n".join(lines)}

@app.post("/n8n/webhook")
async def n8n_webhook(req: TicketRequest):
    result = await pipeline.process_ticket(
        domain=req.domain,
        issue=req.issue,
        ticket_id=req.ticket_id,
        customer_email=req.customer_email
    )
    action = "auto_send" if result["auto_send"] else "flag_for_review"
    return {
        "action": action,
        "confidence": result["diagnosis"]["confidence"],
        "diagnosis": result["diagnosis"]["raw_response"],
        "steps": [{"step": s["step"], "status": s["status"]} for s in result["steps"]]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
