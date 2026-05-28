import json
import re
import logging
from fastapi import APIRouter, Request, Query, Body, HTTPException
from fastapi.responses import HTMLResponse
from app.warehouse.mongo_warehouse import MongoWarehouse
from app.zonewalk.runner import (
    run_zonewalk_full, parse_email_headers, check_propagation,
    whois_lookup, port_scan, check_blocklists, enum_subdomains,
    http_check, run_dig, Resolver, GRID_NS_PATTERNS, COMPETITORS,
)
from app.rag.retriever import retrieve_context_structured

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/htmx")

# Shared warehouse instance (set from main)
_warehouse: MongoWarehouse = None

def init_wh(wh: MongoWarehouse):
    global _warehouse
    _warehouse = wh


def wh():
    if _warehouse is None:
        raise HTTPException(500, "Warehouse not initialized")
    return _warehouse


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def tag(name, content="", cls="", **attrs):
    """Build a simple HTML tag."""
    a = "".join(f' {k}="{esc(v)}"' for k, v in attrs.items() if v is not None)
    c = f' class="{esc(cls)}"' if cls else ""
    return f"<{name}{c}{a}>{content}</{name}>"


def card(title, meta="", preview="", click=None, extra=""):
    onclick = f' onclick="{esc(click)}"' if click else ""
    return f"""<div class="card clickable"{onclick}>
  <div class="title">{title}</div>
  {("<div class=\"meta\">"+meta+"</div>") if meta else ""}
  {("<div class=\"preview\">"+preview+"</div>") if preview else ""}
  {extra}
</div>"""


def section_label(text):
    return f'<div class="section-label">{esc(text)}</div>'


# ─────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────
@router.get("/dashboard", response_class=HTMLResponse)
async def htmx_dashboard():
    return HTMLResponse("""<div class="welcome" style="padding:20px">
  <h2 style="font-size:22px">1-grid Support Agent</h2>
  <p style="margin-bottom:16px;max-width:500px">Diagnose hosting issues, check DNS, analyze mail headers, scan ports, search KB articles.</p>
  <div class="grid" style="gap:8px">
    <div class="crd" onclick="loadView('zonewalk')"><div class="t">🌐 Zonewalk</div><div class="d">Full domain diagnosis</div></div>
    <div class="crd" onclick="loadView('nameservers')"><div class="t">🔗 Nameservers</div><div class="d">1-grid detection</div></div>
    <div class="crd" onclick="loadView('propagation')"><div class="t">📡 Propagation</div><div class="d">DNS propagation check</div></div>
    <div class="crd" onclick="loadView('headers')"><div class="t">📧 Mail Headers</div><div class="d">Parse email headers</div></div>
    <div class="crd" onclick="loadView('logs')"><div class="t">📄 Log Analysis</div><div class="d">Scan error logs</div></div>
    <div class="crd" onclick="loadView('kb')"><div class="t">📚 KB Articles</div><div class="d">Search knowledge base</div></div>
    <div class="crd" onclick="loadView('tickets')"><div class="t">🎫 Tickets</div><div class="d">Search ticket history</div></div>
    <div class="crd" onclick="loadView('dns')"><div class="t">🔎 DNS Lookup</div><div class="d">Dig records</div></div>
    <div class="crd" onclick="loadView('whois')"><div class="t">📇 WHOIS</div><div class="d">Domain registration</div></div>
    <div class="crd" onclick="loadView('ports')"><div class="t">🔌 Port Scan</div><div class="d">Scan open ports</div></div>
    <div class="crd" onclick="loadView('httpcheck')"><div class="t">🌍 HTTP Check</div><div class="d">HTTP + SSL check</div></div>
    <div class="crd" onclick="loadView('blocklists')"><div class="t">🛡️ Blocklists</div><div class="d">IP reputation check</div></div>
    <div class="crd" onclick="loadView('subdomains')"><div class="t">🗂️ Subdomains</div><div class="d">Enumerate subdomains</div></div>
    <div class="crd" onclick="loadView('conversations')"><div class="t">💬 Conversations</div><div class="d">Session history</div></div>
    <div class="crd" onclick="loadView('issues')"><div class="t">🪲 Issues</div><div class="d">All issue history</div></div>
    <div class="crd" onclick="loadView('quickref')"><div class="t">⚡ Quick Ref</div><div class="d">Commands reference</div></div>
    <div class="crd" onclick="loadView('status')"><div class="t">📊 Status</div><div class="d">System status</div></div>
  </div>
</div>""")


# ─────────────────────────────────────────────────────────────────
# TICKETS / HISTORY
# ─────────────────────────────────────────────────────────────────
def _ticket_list_html(tickets):
    if not tickets:
        return '<div class="empty">No tickets found</div>'
    return "".join(
        f"""<div class="card clickable" onclick="loadView('ticket/{esc(t.get('_id',''))}')">
  <div class="title">#{esc(t.get('ticket_ref','?'))} {esc(t.get('domain',''))}</div>
  <div class="meta">
    <span>📅 {esc(t.get('created_at',''))}</span>
    <span>🏷️ {esc(t.get('category',''))}{' / '+esc(t.get('sub_category','')) if t.get('sub_category') else ''}</span>
    <span>📌 {esc(t.get('outcome',''))}</span>
  </div>
  <div class="preview">{esc((t.get('description','') or '')[:200])}</div>
</div>"""
        for t in tickets
    )


@router.get("/history", response_class=HTMLResponse)
async def htmx_history():
    tickets = wh().search_tickets("", 10)
    return HTMLResponse(f"""<div class="search-bar" hx-target="#hres" hx-trigger="keyup[key=='Enter']" hx-get="/htmx/tickets/search" hx-include="#hq">
  <input id="hq" name="q" placeholder="Search domain..." hx-get="/htmx/tickets/search" hx-target="#hres" hx-trigger="keyup[key=='Enter'],search" hx-include="#hq">
  <button hx-get="/htmx/tickets/search" hx-target="#hres" hx-include="#hq">Search</button>
</div>
<div id="hres">{_ticket_list_html(tickets)}</div>""")


@router.get("/tickets", response_class=HTMLResponse)
async def htmx_tickets():
    tickets = wh().search_tickets("", 15)
    return HTMLResponse(f"""<div class="search-bar">
  <input id="tq" name="q" placeholder="Search ticket ref, domain, or keyword..." hx-get="/htmx/tickets/search" hx-target="#tres" hx-trigger="keyup[key=='Enter'],search" hx-include="#tq">
  <button hx-get="/htmx/tickets/search" hx-target="#tres" hx-include="#tq">Search</button>
</div>
<div id="tres">{_ticket_list_html(tickets)}</div>""")


@router.get("/tickets/search", response_class=HTMLResponse)
async def htmx_tickets_search(q: str = ""):
    tickets = wh().search_tickets(q, 30) if q else wh().search_tickets("", 30)
    return HTMLResponse(_ticket_list_html(tickets))


def _ticket_detail_html(t):
    if not t:
        return '<div class="empty">Ticket not found</div>'
    return f"""<div class="article-view">
  <span class="back" onclick="loadView('tickets')">← Back to tickets</span>
  <h2>#{esc(t.get('ticket_ref','?'))} {esc(t.get('domain',''))}</h2>
  <div class="cat">{esc(t.get('category',''))}{' / '+esc(t.get('sub_category','')) if t.get('sub_category') else ''} · {esc(t.get('outcome',''))} · {esc(t.get('created_at',''))}</div>
  <div class="cat">Server: {esc(t.get('server_ip',''))} · PTR: {esc(t.get('ptr',''))} · Channel: {esc(t.get('channel',''))}</div>
  <div class="body">{esc(t.get('description','No description'))}</div>
  {("<div class='body' style='margin-top:12px;color:#94a3b8'>Notes: "+esc(t.get('notes',''))+"</div>") if t.get('notes') else ''}
</div>"""


@router.get("/ticket/{tid}", response_class=HTMLResponse)
async def htmx_ticket_detail(tid: str):
    t = None
    for doc in wh().tickets.find():
        if str(doc.get("_id", "")) == tid:
            t = wh()._serialize(doc)
            break
    return HTMLResponse(_ticket_detail_html(t))


# ─────────────────────────────────────────────────────────────────
# ISSUES
# ─────────────────────────────────────────────────────────────────
@router.get("/issues", response_class=HTMLResponse)
async def htmx_issues():
    issues = wh().search_issues("", 20)
    return HTMLResponse(f"""<div class="search-bar">
  <input id="isq" name="q" placeholder="Search issues..." hx-get="/htmx/issues/search" hx-target="#isres" hx-trigger="keyup[key=='Enter'],search" hx-include="#isq">
  <button hx-get="/htmx/issues/search" hx-target="#isres" hx-include="#isq">Search</button>
</div>
<div id="isres">{_issues_list_html(issues)}</div>""")


@router.get("/issues/search", response_class=HTMLResponse)
async def htmx_issues_search(q: str = ""):
    issues = wh().search_issues(q, 20)
    return HTMLResponse(_issues_list_html(issues))


def _issues_list_html(issues):
    if not issues:
        return '<div class="empty">No issues found</div>'
    return "".join(
        f"""<div class="card clickable" onclick="loadView('issue/{esc(i.get('_id',''))}')">
  <div class="title">{esc(i.get('domain',''))} <span style="font-weight:400;font-size:11px;color:#64748b">#{esc(i.get('ticket_ref','?'))}</span></div>
  <div class="meta">
    <span>📅 {esc(i.get('created_at',''))}</span>
    <span>🏷️ {esc(i.get('issue_type',''))}</span>
    <span>📌 <span class="{'green' if i.get('status')=='resolved' else 'red'}">{esc(i.get('status',''))}</span></span>
  </div>
  <div class="preview">{esc((i.get('issue_summary','') or '')[:200])}</div>
</div>"""
        for i in issues
    )


@router.get("/issue/{iid}", response_class=HTMLResponse)
async def htmx_issue_detail(iid: str):
    iss = None
    for doc in wh().issues.find():
        if str(doc.get("_id", "")) == iid:
            iss = wh()._serialize(doc)
            break
    if not iss:
        return HTMLResponse('<div class="empty">Issue not found</div>')
    status_cls = "green" if iss.get("status") == "resolved" else "red"
    return HTMLResponse(f"""<div class="article-view">
  <span class="back" onclick="loadView('issues')">← Back to issues</span>
  <h2>{esc(iss.get('domain',''))} <span style="font-weight:400;font-size:14px;color:#64748b">#{esc(iss.get('ticket_ref','?'))}</span></h2>
  <div class="cat">{esc(iss.get('issue_type',''))} · {esc(iss.get('hosting_type',''))} · <span class="{status_cls}">{esc(iss.get('status',''))}</span></div>
  <div class="details-grid" style="margin-bottom:10px">
    <span class="k">Server</span><span class="v mono">{esc(iss.get('server_ip',''))}</span>
    {("<span class='k'>PTR</span><span class='v mono'>"+esc(iss.get('ptr',''))+"</span>") if iss.get('ptr') else ""}
    {("<span class='k'>NS</span><span class='v mono'>"+esc(iss.get('nameservers',''))+"</span>") if iss.get('nameservers') else ""}
    <span class="k">Ticket</span><span class="v">{esc(iss.get('ticket_ref',''))}</span>
    <span class="k">Source</span><span class="v">{esc(iss.get('source',''))}</span>
  </div>
  <div class="section-label">Summary</div>
  <div class="body">{esc(iss.get('issue_summary','No summary'))}</div>
  {("<div class='section-label' style='margin-top:10px'>Resolution</div><div class='body' style='color:#86efac'>"+esc(iss.get('resolution',''))+"</div>") if iss.get('resolution') else ''}
</div>""")


# ─────────────────────────────────────────────────────────────────
# CONVERSATIONS
# ─────────────────────────────────────────────────────────────────
@router.get("/conversations", response_class=HTMLResponse)
async def htmx_conversations():
    convs = wh().get_conversations(50)
    items = "".join(
        f"""<div class="card clickable" onclick="loadView('conversation/{esc(c.get('_id',''))}')">
  <div class="title">💬 {esc(c.get('source','unknown'))} · {esc(str(c.get('id',''))[:24])}</div>
  <div class="meta">
    <span>📅 {esc(c.get('timestamp',''))}</span>
    <span>💬 {len(c.get('messages',[]))} messages</span>
    <span>⚡ {len(c.get('commands',[]))} commands</span>
  </div>
  <div class="preview">{esc((c.get('messages',[{}])[0].get('content','') or '')[:120])}</div>
</div>"""
        for c in convs
    )
    return HTMLResponse(f"""<div class="search-bar">
  <input id="cvq" placeholder="Filter conversations..." hx-get="/htmx/conversations/search" hx-target="#cvres" hx-trigger="keyup changed delay:200ms" hx-include="#cvq">
  <button hx-get="/htmx/conversations/search" hx-target="#cvres" hx-include="#cvq">Filter</button>
</div>
<div id="cvres">{items or '<div class="empty">No conversations</div>'}</div>""")


@router.get("/conversations/search", response_class=HTMLResponse)
async def htmx_conversations_search(q: str = ""):
    convs = wh().get_conversations(50)
    if q:
        ql = q.lower()
        convs = [c for c in convs if ql in json.dumps(c).lower()]
    items = "".join(
        f"""<div class="card clickable" onclick="loadView('conversation/{esc(c.get('_id',''))}')">
  <div class="title">💬 {esc(c.get('source','unknown'))} · {esc(str(c.get('id',''))[:24])}</div>
  <div class="meta"><span>📅 {esc(c.get('timestamp',''))}</span><span>💬 {len(c.get('messages',[]))} messages</span></div>
  <div class="preview">{esc((c.get('messages',[{}])[0].get('content','') or '')[:120])}</div>
</div>"""
        for c in convs
    )
    return HTMLResponse(items or '<div class="empty">No matching conversations</div>')


@router.get("/conversation/{cid}", response_class=HTMLResponse)
async def htmx_conversation_detail(cid: str):
    cv = None
    for doc in wh().conversations.find():
        if str(doc.get("_id", "")) == cid:
            cv = wh()._serialize(doc)
            break
    if not cv:
        return HTMLResponse('<div class="empty">Conversation not found</div>')
    msgs = cv.get("messages", [])
    cmds = cv.get("commands", [])
    msg_html = "".join(
        f"""<div class="card" style="margin-bottom:4px;{'border-color:#2563eb' if m.get('role')=='user' else ''}">
  <div class="meta">{'👤 User' if m.get('role')=='user' else '🤖 Assistant'}</div>
  <div class="body" style="font-size:12px;margin-top:2px">{esc((m.get('content','') or '')[:1000])}</div>
</div>"""
        for m in msgs
    )
    cmd_html = ""
    if cmds:
        cmd_html = f"""<div class="section-label">Commands ({len(cmds)})</div>
{''.join(f'<div class="card" style="padding:5px 10px;margin-bottom:2px"><div class="val mono" style="font-size:11px">{esc(c.get("command",""))}</div><div class="preview" style="font-size:10px">{esc((c.get("output","") or "")[:200])}</div></div>' for c in cmds)}"""
    return HTMLResponse(f"""<div class="article-view">
  <span class="back" onclick="loadView('conversations')">← Back to conversations</span>
  <h2>💬 {esc(cv.get('source','Session'))}</h2>
  <div class="cat">{esc(str(cv.get('id','')))} · {esc(cv.get('timestamp',''))} · {len(msgs)} messages</div>
  {msg_html}
  {cmd_html}
</div>""")


# ─────────────────────────────────────────────────────────────────
# SERVERS
# ─────────────────────────────────────────────────────────────────
@router.get("/servers", response_class=HTMLResponse)
async def htmx_servers():
    servers = wh().servers_enriched()
    return HTMLResponse(f"""<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">{len(servers)} server IPs from tickets with ticket counts</div>
<div class="search-bar">
  <input id="svq" placeholder="Filter..." hx-get="/htmx/servers/search" hx-target="#svres" hx-trigger="keyup changed delay:200ms" hx-include="#svq">
  <button hx-get="/htmx/servers/search" hx-target="#svres" hx-include="#svq">Filter</button>
</div>
<div id="svres">{_servers_list_html(servers)}</div>""")


@router.get("/servers/search", response_class=HTMLResponse)
async def htmx_servers_search(q: str = ""):
    servers = wh().servers_enriched()
    if q:
        ql = q.lower()
        servers = [s for s in servers if ql in json.dumps(s).lower()]
    return HTMLResponse(_servers_list_html(servers))


def _servers_list_html(servers):
    if not servers:
        return '<div class="empty">No servers found</div>'
    return "".join(
        f"""<div class="card" style="margin-bottom:4px">
  <div class="title">🖥️ {esc(s.get('server_ip',''))} {('('+esc(s.get('ptr',''))+')') if s.get('ptr') else ''}</div>
  <div class="meta">
    <span>{esc(s.get('hostname',''))}</span>
    <span>📋 {s.get('count',0)} tickets</span>
    {('<span>'+esc(s.get('hosting_type',''))+'</span>') if s.get('hosting_type') else ''}
  </div>
  {('<div class="preview">🌐 '+esc(s.get('domains',''))+'</div>') if s.get('domains') else ''}
  {('<div class="preview">🏷️ '+esc(s.get('categories',''))+'</div>') if s.get('categories') else ''}
  {('<div class="preview">📌 '+esc(s.get('outcomes',''))+'</div>') if s.get('outcomes') else ''}
  {('<div class="preview" style="color:#f87171">⚠️ '+esc(s.get('known_issues',''))+'</div>') if s.get('known_issues') else ''}
</div>"""
        for s in servers
    )


# ─────────────────────────────────────────────────────────────────
# PATTERNS (tickets by server)
# ─────────────────────────────────────────────────────────────────
@router.get("/patterns", response_class=HTMLResponse)
async def htmx_patterns():
    servers = wh().tickets_by_server()
    if not servers:
        return HTMLResponse('<div class="empty">No patterns found</div>')
    items = "".join(
        f"""<div class="card clickable" style="margin-bottom:6px" onclick="loadView('patterns/{esc(s.get('server_ip',''))}')">
  <div class="title">🖥️ {esc(s.get('server_ip','Unknown'))} {('('+esc(s.get('ptr',''))+')') if s.get('ptr') else ''}</div>
  <div class="meta"><span>📋 {s['count']} tickets</span><span>🏷️ {esc(s.get('categories',''))}</span></div>
  <div class="meta"><span>🌐 {esc(s.get('domains',''))}</span></div>
  {('<div class="meta"><span>📌 '+esc(s.get('outcomes',''))+'</span></div>') if s.get('outcomes') else ''}
</div>"""
        for s in servers
    )
    return HTMLResponse(f'<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Tickets grouped by server IP</div>{items}')


@router.get("/patterns/{ip}", response_class=HTMLResponse)
async def htmx_patterns_by_ip(ip: str):
    tickets = wh().search_tickets(ip, 30)
    return HTMLResponse(f"""<div style="margin-bottom:6px"><span class="back" onclick="loadView('patterns')" style="font-size:12px;color:#2563eb;cursor:pointer">← Back to patterns</span></div>
{_ticket_list_html(tickets)}""")


# ─────────────────────────────────────────────────────────────────
# KB
# ─────────────────────────────────────────────────────────────────
@router.get("/kb", response_class=HTMLResponse)
async def htmx_kb():
    return HTMLResponse(f"""<div class="search-bar">
  <input id="kbq" name="q" placeholder="Search KB articles..." hx-get="/htmx/kb/search" hx-target="#kbres" hx-trigger="keyup[key=='Enter'],search" hx-include="#kbq">
  <button hx-get="/htmx/kb/search" hx-target="#kbres" hx-include="#kbq">Search</button>
  <button class="green sm" hx-get="/htmx/kb/browse" hx-target="#kbres">Browse All</button>
</div>
<div id="kbres" hx-get="/htmx/kb/browse" hx-trigger="load"></div>
<div style="margin-top:6px;font-size:11px;color:#475569" id="kbcount"></div>""")


def renderKBArticle(a):
    return f"""<div class="card clickable" onclick="loadView('kb/{esc(a.get('title',''))}')">
  <div class="title">{esc(a.get('title',''))}</div>
  <div class="meta"><span>📂 {esc(a.get('category','General'))}</span></div>
  <div class="preview">{esc((a.get('content','') or '')[:200])}</div>
</div>"""


@router.get("/kb/search", response_class=HTMLResponse)
async def htmx_kb_search(q: str = ""):
    if not q:
        return HTMLResponse('<div class="empty">Type a search term</div>')
    try:
        results = retrieve_context_structured(q, 15)
        articles = []
        for r in results:
            articles.append({
                "title": r["metadata"].get("title", ""),
                "category": r["metadata"].get("category", ""),
                "content": r["content"][:2000],
                "distance": r.get("distance", 0),
            })
        if not articles:
            return HTMLResponse('<div class="empty">No articles found</div>')
        return HTMLResponse("".join(renderKBArticle(a) for a in articles))
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Search failed: {esc(str(e))}</div>')


@router.get("/kb/browse", response_class=HTMLResponse)
async def htmx_kb_browse():
    try:
        results = retrieve_context_structured("email dns security domain hosting backup", 30)
        articles = []
        for r in results:
            articles.append({
                "title": r["metadata"].get("title", ""),
                "category": r["metadata"].get("category", ""),
                "content": r["content"][:2000],
                "distance": r.get("distance", 0),
            })
        if not articles:
            return HTMLResponse('<div class="empty">No articles found</div>')
        return HTMLResponse("".join(renderKBArticle(a) for a in articles))
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Failed: {esc(str(e))}</div>')


@router.get("/kb/{title}", response_class=HTMLResponse)
async def htmx_kb_detail(title: str):
    try:
        results = retrieve_context_structured(title, 20)
        article = None
        for r in results:
            if r["metadata"].get("title", "").lower() == title.lower():
                article = {
                    "title": r["metadata"].get("title", ""),
                    "category": r["metadata"].get("category", ""),
                    "content": r["content"],
                }
                break
        if not article:
            return HTMLResponse('<div class="empty">Article not found</div>')
        return HTMLResponse(f"""<div class="article-view">
  <span class="back" onclick="loadView('kb')">← Back to KB search</span>
  <h2>{esc(article.get('title',''))}</h2>
  <div class="cat">📂 {esc(article.get('category','General'))}</div>
  <div class="body">{esc(article.get('content',''))}</div>
</div>""")
    except:
        return HTMLResponse('<div class="empty">Failed to load article</div>')


# ─────────────────────────────────────────────────────────────────
# QUICK REF
# ─────────────────────────────────────────────────────────────────
@router.get("/quickref", response_class=HTMLResponse)
async def htmx_quickref():
    groups = wh().quickref_by_category()
    cats = list(groups.keys())
    if not cats:
        return HTMLResponse('<div class="empty">No quick references</div>')
    html = '<input id="qrf" style="width:100%;padding:8px 12px;border:1px solid #334155;border-radius:6px;background:#1e293b;color:#e2e8f0;font-size:13px;outline:none;margin-bottom:8px" placeholder="Filter references..." oninput="filterQuickRef(this.value)">'
    html += '<div id="qrlist">'
    for cat in cats:
        html += f'<div class="qr-cat" data-cat="{esc(cat)}"><div style="font-size:11px;color:#94a3b8;font-weight:500;margin:8px 0 3px 4px">{esc(cat)}</div>'
        for r in groups[cat]:
            val = r.get("value", "")
            kname = r.get("key_name", "")
            search_data = f"{kname} {cat} {val}".lower()
            html += f"""<div class="card clickable qr-item" style="margin-bottom:3px" data-search="{esc(search_data)}" onclick="navigator.clipboard.writeText({json.dumps(val)});toast('Copied!')">
  <div class="title">{esc(kname)}</div>
  <div class="preview" style="font-family:monospace;font-size:11px;color:#a5b4fc">{esc(val)}</div>
</div>"""
        html += "</div>"
    html += "</div>"
    html += """<script>
function filterQuickRef(val) {
  const q = val.toLowerCase();
  document.querySelectorAll('.qr-item').forEach(el => { el.style.display = el.dataset.search.includes(q) ? '' : 'none'; });
  document.querySelectorAll('.qr-cat').forEach(el => {
    const visible = [...el.querySelectorAll('.qr-item')].some(e => e.style.display !== 'none');
    el.style.display = visible ? '' : 'none';
  });
}
function toast(msg) {
  const el=document.createElement('div');
  el.style.cssText='position:fixed;bottom:60px;left:50%;transform:translateX(-50%);background:#2563eb;color:#fff;padding:8px 16px;border-radius:6px;font-size:13px;z-index:999';
  el.textContent=msg;document.body.appendChild(el);setTimeout(()=>el.remove(),2000);
}
</script>"""
    return HTMLResponse(html)


# ─────────────────────────────────────────────────────────────────
# STATUS
# ─────────────────────────────────────────────────────────────────
@router.get("/status", response_class=HTMLResponse)
async def htmx_status():
    import httpx
    h = o = {"status": "unknown"}
    t = {"tickets": None}
    try:
        h = httpx.get("http://localhost:8000/health", timeout=3).json()
    except:
        pass
    try:
        o = httpx.get("http://localhost:8000/health/ollama", timeout=3).json()
    except:
        pass
    try:
        t = httpx.get("http://localhost:8000/tickets?limit=1", timeout=3).json()
    except:
        pass
    ticket_count = f"{len(t.get('tickets',[]))}+" if t.get("tickets") else "?"
    return HTMLResponse(f"""<div class="card"><div class="title">📊 System Status</div></div>
<div class="card" style="margin-top:4px">
  <div class="title">Server</div>
  <div class="meta"><span>Status: {esc(h.get('status','unknown'))}</span><span>Model: {esc(h.get('model','N/A'))}</span></div>
</div>
<div class="card" style="margin-top:4px">
  <div class="title">Ollama</div>
  <div class="meta"><span>Status: {esc(o.get('status','disconnected'))}</span><span>Model: {esc(o.get('model','none'))}</span></div>
</div>
<div class="card" style="margin-top:4px">
  <div class="title">Database</div>
  <div class="meta"><span>Type: MongoDB 1grid</span><span>Tickets: {ticket_count}</span></div>
</div>
<div class="card" style="margin-top:4px">
  <div class="title">Zonewalk</div>
  <div class="meta"><span>Mode: Python native</span><span>DNS: dnspython</span></div>
</div>""")


# ─────────────────────────────────────────────────────────────────
# TOOL: ZONEWALK
# ─────────────────────────────────────────────────────────────────
@router.get("/zonewalk", response_class=HTMLResponse)
async def htmx_zonewalk():
    return HTMLResponse("""<div class="search-bar">
  <input id="zwd" name="domain" placeholder="Domain to diagnose (e.g. purify1.co.za)" hx-post="/htmx/zonewalk/run" hx-target="#zwres" hx-trigger="keyup[key=='Enter']" hx-include="#deep">
  <button hx-post="/htmx/zonewalk/run" hx-target="#zwres" hx-include="#deep,#zwd">Zonewalk</button>
  <button class="amber" hx-post="/htmx/zonewalk/run" hx-target="#zwres" hx-include="#zwd" hx-vals='{"deep":"true"}'>Deep Scan</button>
  <input type="hidden" id="deep" name="deep" value="false">
</div>
<div id="zwres"></div>""")


@router.post("/zonewalk/run", response_class=HTMLResponse)
async def htmx_zonewalk_run(domain: str = "", deep: str = "false"):
    if not domain:
        return HTMLResponse('<div class="empty">Enter a domain</div>')
    deep_bool = deep.lower() in ("true", "1", "yes")
    try:
        d = run_zonewalk_full(domain, deep=deep_bool, ports=deep_bool, reputation=deep_bool).to_dict()
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')
    html = ""
    # Provider badge
    provider_label = "1-grid" if d.get("is_grid") else (d.get("hosting_provider", "Unknown"))
    badge_cls = "grid" if d.get("is_grid") else ("external" if d.get("hosting_provider") != "Unknown / External" else "unknown")
    html += f"""<div class="detect-box" style="margin-bottom:8px">
  <span class="badge {badge_cls}">{esc(provider_label)}</span>
  <span style="font-size:13px">{esc(d.get('domain',''))}</span>
  {('<span style="font-size:11px;color:#64748b">'+esc(d.get('hosting_type',''))+'</span>') if d.get('hosting_type') else ''}
</div>"""
    # NS
    if d.get("nameservers"):
        html += section_label("Nameservers") + "".join(f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="val mono">{esc(ns)}</div></div>' for ns in d["nameservers"])
    # DNS records
    html += section_label("DNS Records")
    html += '<div class="details-grid" style="margin-bottom:6px">'
    a_recs = d.get("a_records", [])
    html += f'<span class="k">A Record</span><span class="v mono">{esc(", ".join(a_recs)) if a_recs else "NONE"}</span>'
    ptr = d.get("ptr_record", "")
    html += f'<span class="k">PTR</span><span class="v mono{' red' if not ptr else ''}">{esc(ptr) if ptr else "No PTR"}</span>'
    if ptr and domain and ptr not in domain:
        html += f'<span class="k"></span><span class="v red">⚠ PTR mismatch</span>'
    if d.get("mx_records"):
        html += f'<span class="k">MX</span><span class="v mono">{esc(", ".join(m[1] for m in d["mx_records"]))}</span>'
    if d.get("soa"):
        html += f'<span class="k">SOA</span><span class="v mono">{esc(d["soa"].get("mname",""))} · serial {d["soa"].get("serial","?")}</span>'
    html += "</div>"
    # Mail auth
    html += section_label("Mail Authentication")
    spf = "OK" if d.get("spf_record") else "MISSING"
    dkim = "OK" if d.get("dkim_records") else "MISSING"
    dmarc = "OK" if d.get("dmarc_record") else "MISSING"
    html += f"""<div class="details-grid" style="margin-bottom:6px">
  <span class="k">SPF</span><span class="v {'green' if spf=='OK' else 'red'}">{spf}</span>
  <span class="k">DKIM</span><span class="v {'green' if dkim=='OK' else 'red'}">{dkim}</span>
  <span class="k">DMARC</span><span class="v {'green' if dmarc=='OK' else 'red'}">{dmarc}</span>
  {('<span class="k">MailChannels</span><span class="v green">Authorised</span>') if d.get('has_mailchannels') else ''}
</div>"""
    # HTTP/SSL
    if d.get("http_status") or d.get("https_status"):
        html += section_label("Web / SSL")
        html += '<div class="details-grid" style="margin-bottom:6px">'
        if d.get("http_status"):
            html += f'<span class="k">HTTP</span><span class="v">{d["http_status"]["status_code"]}</span>'
        if d.get("https_status"):
            html += f'<span class="k">HTTPS</span><span class="v">{d["https_status"]["status_code"]}</span>'
        ssl_days = d.get("ssl_expiry_days")
        if ssl_days is not None:
            ssl_cls = "red" if ssl_days < 14 else ("amber" if ssl_days < 60 else "green")
            html += f'<span class="k">SSL</span><span class="v {ssl_cls}">{ssl_days} days</span>'
        html += "</div>"
    # Ports
    if d.get("open_ports"):
        html += section_label("Open Ports") + '<div class="flex-row" style="margin-bottom:6px">'
        for p in d["open_ports"]:
            html += f'<span class="c" style="background:#1e293b;border:1px solid #334155;padding:2px 8px;border-radius:4px;font-size:11px">{p[1]} ({p[0]})</span>'
        html += "</div>"
    # Propagation
    if d.get("propagation"):
        html += section_label("DNS Propagation") + '<div class="prop-grid" style="margin-bottom:6px">'
        for p in d["propagation"]:
            cls = "green" if p.get("match") else "red"
            html += f'<div class="prop-item"><div class="rname">{esc(p.get("resolver",""))}</div><div class="rip">{p.get("ip","")}</div><div class="rresult {cls}">{esc(", ".join(p.get("result",[]))) if p.get("result") else "NONE"} {"✓" if p.get("match") else "✗"}</div></div>'
        html += "</div>"
    # Blocklists
    if d.get("blocklists"):
        html += section_label("IP Reputation") + '<div class="flex-row" style="margin-bottom:6px">'
        for b in d["blocklists"]:
            bcls = "red" if b.get("listed") else "green"
            html += f'<span class="c" style="background:#1e293b;border:1px solid #334155;padding:2px 8px;border-radius:4px;font-size:11px;color:{"#f87171" if b.get("listed") else "#4ade80"}">{esc(b.get("list",""))}: {"LISTED" if b.get("listed") else "Clean"}</span>'
        html += "</div>"
    # Subdomains
    if d.get("subdomains"):
        html += section_label("Subdomains Found")
        for sd in d["subdomains"]:
            info = ", ".join(sd.get("ips",[])) if sd.get("ips") else (f'CNAME {sd.get("cname","")}' if sd.get("cname") else "")
            html += f'<div class="card" style="padding:5px 10px;margin-bottom:2px"><div class="val mono">{esc(sd.get("subdomain",""))} → {esc(info)}</div></div>'
    # Issues
    if d.get("issues"):
        html += section_label("Issues Found")
        for iss in d["issues"]:
            icls = "red" if iss.startswith("NO_") or iss.startswith("HTTP_5") or iss.startswith("SSL_EXP") else "amber"
            html += f'<div style="padding:3px 0;font-size:12px;color:{"#f87171" if icls=="red" else "#facc15"}">⚠ {esc(iss)}</div>'
    # WHOIS
    if d.get("whois") and d["whois"].get("registrar"):
        html += section_label("WHOIS") + '<div class="details-grid">'
        html += f'<span class="k">Registrar</span><span class="v">{esc(d["whois"]["registrar"])}</span>'
        if d["whois"].get("expiry"):
            html += f'<span class="k">Expiry</span><span class="v">{esc(d["whois"]["expiry"])}</span>'
        html += "</div>"
    return HTMLResponse(html)


# ─────────────────────────────────────────────────────────────────
# TOOL: MAIL HEADERS
# ─────────────────────────────────────────────────────────────────
@router.get("/headers", response_class=HTMLResponse)
async def htmx_headers():
    return HTMLResponse("""<div style="display:flex;flex-direction:column;gap:8px;height:100%">
  <div style="font-size:12px;color:#94a3b8">Paste raw email headers below. Parses SPF, DKIM, DMARC, Received chain.</div>
  <textarea id="mh" name="headers" placeholder="Paste headers here..." style="min-height:140px;padding:10px;border:1px solid #334155;border-radius:6px;background:#1e293b;color:#e2e8f0;font-size:12px;font-family:monospace;outline:none;resize:vertical"></textarea>
  <div><button hx-post="/htmx/headers/analyze" hx-target="#mhres" hx-include="#mh" hx-indicator="#mhspinner">Analyze Headers</button><span id="mhspinner" class="htmx-indicator" style="margin-left:8px;color:#64748b;font-size:12px">Analyzing...</span></div>
  <div id="mhres"></div>
</div>""")


@router.post("/headers/analyze", response_class=HTMLResponse)
async def htmx_headers_analyze(headers: str = Body(...)):
    if not headers.strip():
        return HTMLResponse('<div class="empty">Paste headers first</div>')
    try:
        d = parse_email_headers(headers)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')
    html = ""
    if d.get("block_reason"):
        html += f'<div class="card" style="border-color:#ef4444;margin-bottom:8px"><div class="title" style="color:#f87171">⛔ Block Detected</div><div class="val" style="color:#fca5a5">{esc(d["block_reason"])}</div></div>'
    html += section_label("Header Fields") + '<div class="details-grid" style="margin-bottom:8px">'
    for k, v in [("From", d.get("from")), ("To", d.get("to")), ("Subject", d.get("subject")), ("Date", d.get("date")),
                 ("Return-Path", d.get("return_path")), ("Reply-To", d.get("reply_to")),
                 ("Originating IP", d.get("originating_ip")), ("Spam Score", d.get("spam_score"))]:
        if v: html += f'<span class="k">{k}</span><span class="v mono">{esc(str(v))}</span>'
    html += "</div>"
    html += section_label("Authentication") + '<div class="details-grid" style="margin-bottom:8px">'
    for k, v in [("SPF", d.get("spf_result")), ("DKIM", d.get("dkim_result")), ("DMARC", d.get("dmarc_result")), ("ARC", d.get("arc_result"))]:
        if v: html += f'<span class="k">{k}</span><span class="v {"green" if v=="pass" else "red"}">{esc(v)}</span>'
    html += "</div>"
    if d.get("hops"):
        html += section_label(f"Received Chain ({len(d['hops'])} hops)")
        for i, h in enumerate(d["hops"]):
            label = "Origin" if i == 0 else ("Final" if i == len(d["hops"])-1 else f"Hop {i+1}")
            html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div style="font-size:10px;color:#64748b;margin-bottom:2px">{label}</div><div class="val mono" style="font-size:11px">{esc(h[:200])}</div></div>'
    return HTMLResponse(html)


# ─────────────────────────────────────────────────────────────────
# TOOL: PROPAGATION
# ─────────────────────────────────────────────────────────────────
@router.get("/propagation", response_class=HTMLResponse)
async def htmx_propagation():
    return HTMLResponse("""<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Check DNS propagation across global resolvers</div>
<div class="search-bar">
  <input id="ppd" name="domain" placeholder="Domain" hx-post="/htmx/propagation/check" hx-target="#ppres" hx-trigger="keyup[key=='Enter']">
  <button hx-post="/htmx/propagation/check" hx-target="#ppres" hx-include="#ppd">Check Propagation</button>
</div>
<div id="ppres"></div>""")


@router.post("/propagation/check", response_class=HTMLResponse)
async def htmx_propagation_check(domain: str = Body("")):
    if not domain:
        return HTMLResponse('<div class="empty">Enter a domain</div>')
    try:
        res = Resolver()
        a_records = res.a(domain)
        if not a_records:
            return HTMLResponse(f'<div class="card" style="margin-bottom:8px"><div class="title">📡 {esc(domain)}</div><div class="meta">No A records found</div></div>')
        prop = check_propagation(domain, a_records)
        html = f'<div class="card" style="margin-bottom:8px"><div class="title">📡 {esc(domain)}</div><div class="meta">A records: {esc(", ".join(a_records))}</div></div>'
        if prop:
            html += '<div class="prop-grid">'
            for p in prop:
                cls = "green" if p.get("match") else "red"
                html += f"""<div class="prop-item">
  <div class="rname">{esc(p.get("resolver",""))} {"✓" if p.get("match") else "✗"}</div>
  <div class="rip">{p.get("ip","")}</div>
  <div class="rresult {cls}">{esc(", ".join(p.get("result",[]))) if p.get("result") else "NONE"}</div>
</div>"""
            html += "</div>"
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')


# ─────────────────────────────────────────────────────────────────
# TOOL: NAMESERVERS
# ─────────────────────────────────────────────────────────────────
@router.get("/nameservers", response_class=HTMLResponse)
async def htmx_nameservers():
    return HTMLResponse("""<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Check nameservers and detect hosting provider</div>
<div class="search-bar">
  <input id="nsd" name="domain" placeholder="Domain" hx-post="/htmx/nameservers/check" hx-target="#nsres" hx-trigger="keyup[key=='Enter']">
  <button hx-post="/htmx/nameservers/check" hx-target="#nsres" hx-include="#nsd">Check NS</button>
</div>
<div id="nsres"></div>""")


@router.post("/nameservers/check", response_class=HTMLResponse)
async def htmx_nameservers_check(domain: str = Body("")):
    if not domain:
        return HTMLResponse('<div class="empty">Enter a domain</div>')
    try:
        res = Resolver()
        ns = res.ns(domain)
        is_grid = False
        provider = "Unknown"
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
        cls = "grid" if is_grid else "external"
        html = f"""<div class="detect-box" style="margin-bottom:8px">
  <span class="badge {cls}">{esc(provider)}</span>
  <span style="font-size:13px">{esc(domain)}</span>
  {('<span style="font-size:11px;color:#64748b">'+esc(hosting_type)+'</span>') if hosting_type else ''}
</div>
{section_label("Nameserver Records")}
{''.join(f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="val mono">{esc(ns_host)}</div></div>' for ns_host in ns)}"""
        if provider and not is_grid:
            html += f'<div class="card" style="margin-top:6px;border-color:#7c2d12"><div class="title" style="color:#fdba74">⚠ External Hosting</div><div class="preview">This domain uses {esc(provider)} nameservers. NOT hosted with 1-grid.</div></div>'
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')


# ─────────────────────────────────────────────────────────────────
# TOOL: LOG ANALYSIS
# ─────────────────────────────────────────────────────────────────
@router.get("/logs", response_class=HTMLResponse)
async def htmx_logs():
    return HTMLResponse("""<div style="display:flex;flex-direction:column;gap:8px;height:100%">
  <div style="font-size:12px;color:#94a3b8">Paste error logs. Detects PHP errors, MySQL, HTTP codes, WordPress, timeouts, disk/memory limits.</div>
  <textarea id="lg" name="content" placeholder="Paste log content..." style="min-height:160px;padding:10px;border:1px solid #334155;border-radius:6px;background:#1e293b;color:#e2e8f0;font-size:12px;font-family:monospace;outline:none;resize:vertical"></textarea>
  <div><button class="amber" hx-post="/htmx/logs/analyze" hx-target="#lgres" hx-include="#lg">Analyze Logs</button></div>
  <div id="lgres"></div>
</div>""")


@router.post("/logs/analyze", response_class=HTMLResponse)
async def htmx_logs_analyze(content: str = Body("")):
    if not content.strip():
        return HTMLResponse('<div class="empty">Paste logs first</div>')
    text = content
    lines = text.split("\n")
    findings = []
    for pattern, ftype, label in [
        (r"PHP\s+(Fatal|Warning|Notice|Parse|Error)", "PHP_Errors", "🐘"),
        (r"(MySQL|MariaDB|mysqli|PDOException|SQLSTATE)", "MySQL_Errors", "🗄️"),
        (r"\s(401|403|404)\s", "HTTP_4xx", "🚫"),
        (r"\s(500|502|503|504)\s", "HTTP_5xx", "💥"),
        (r"(WordPress|wp_|WPDB|wp_error)", "WordPress", "🔗"),
        (r"(timeout|timed\s*out|connection\s+refused)", "Connection_Timeout", "⏱️"),
        (r"(disk\s+full|out\s+of\s+memory|memory\s+exhausted|disk\s+quota)", "Resource_Limit", "💾"),
        (r"(permission\s+denied|cannot\s+open|failed\s+to\s+open)", "Permission_Denied", "🔒"),
    ]:
        matches = [l for l in lines if re.search(pattern, l, re.I)]
        if matches:
            findings.append({"type": ftype, "icon": label, "count": len(matches), "samples": matches[:5]})
    if not findings:
        return HTMLResponse(f'<div class="card"><div class="title">No patterns detected</div><div class="meta">{len(lines)} lines scanned</div></div>')
    html = f'<div class="card" style="margin-bottom:8px"><div class="title">📄 Log Analysis</div><div class="meta">{len(lines)} lines · {len(findings)} pattern types</div></div>'
    for f in findings:
        html += f"""<div class="card" style="margin-bottom:4px;{('border-color:#7f1d1d') if f['type'] in ('HTTP_5xx','Resource_Limit') else ''}">
  <div class="title">{f['icon']} {esc(f['type'].replace('_',' '))} <span style="font-weight:400;color:#64748b">({f['count']} occurrences)</span></div>
  {''.join(f'<div class="preview mono" style="font-family:monospace;font-size:11px;padding:2px 0">{esc(s[:200])}</div>' for s in f['samples'])}
</div>"""
    return HTMLResponse(html)


# ─────────────────────────────────────────────────────────────────
# TOOL: DNS LOOKUP
# ─────────────────────────────────────────────────────────────────
@router.get("/dns", response_class=HTMLResponse)
async def htmx_dns():
    return HTMLResponse("""<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">DNS record lookup (dig equivalent)</div>
<div class="search-bar">
  <input id="dnsd" name="domain" placeholder="Domain" style="flex:2">
  <select id="dnst" name="query_type" style="padding:8px 10px;border:1px solid #334155;border-radius:6px;background:#1e293b;color:#e2e8f0;font-size:12px;outline:none">
    <option value="ANY">ANY</option><option value="A">A</option><option value="AAAA">AAAA</option>
    <option value="MX">MX</option><option value="NS">NS</option><option value="TXT">TXT</option>
    <option value="CNAME">CNAME</option><option value="SOA">SOA</option>
  </select>
  <button hx-post="/htmx/dns/lookup" hx-target="#dnsres" hx-include="#dnsd,#dnst">Lookup</button>
</div>
<div id="dnsres"></div>""")


@router.post("/dns/lookup", response_class=HTMLResponse)
async def htmx_dns_lookup(domain: str = Body(""), query_type: str = Body("ANY")):
    if not domain:
        return HTMLResponse('<div class="empty">Enter a domain</div>')
    try:
        d = run_dig(domain, query_type)
        results = d.get("stdout", "")
        if isinstance(results, str) and results.startswith("["):
            results = json.loads(results)
        html = f'<div class="card" style="margin-bottom:6px"><div class="title">🔎 {esc(domain)} {query_type}</div></div>'
        if isinstance(results, list):
            for r in results:
                html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="val mono">{esc(r)}</div></div>'
        else:
            html += f'<div class="card" style="padding:6px 10px"><div class="val mono">{esc(str(results))}</div></div>'
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')


# ─────────────────────────────────────────────────────────────────
# TOOL: WHOIS
# ─────────────────────────────────────────────────────────────────
@router.get("/whois", response_class=HTMLResponse)
async def htmx_whois():
    return HTMLResponse("""<div class="search-bar">
  <input id="whd" name="domain" placeholder="Domain" hx-post="/htmx/whois/lookup" hx-target="#whres" hx-trigger="keyup[key=='Enter']">
  <button hx-post="/htmx/whois/lookup" hx-target="#whres" hx-include="#whd">WHOIS Lookup</button>
</div>
<div id="whres"></div>""")


@router.post("/whois/lookup", response_class=HTMLResponse)
async def htmx_whois_lookup(domain: str = Body("")):
    if not domain:
        return HTMLResponse('<div class="empty">Enter a domain</div>')
    try:
        d = whois_lookup(domain)
        html = f'<div class="card" style="margin-bottom:6px"><div class="title">📇 {esc(domain)}</div></div>'
        html += '<div class="details-grid">'
        if d.get("registrar"): html += f'<span class="k">Registrar</span><span class="v">{esc(d["registrar"])}</span>'
        if d.get("expiry"): html += f'<span class="k">Expiry</span><span class="v">{esc(d["expiry"])}</span>'
        if d.get("status"): html += f'<span class="k">Status</span><span class="v">{esc(d["status"])}</span>'
        html += '</div>'
        if d.get("raw"):
            html += f'<div class="card" style="margin-top:6px"><div class="title">Raw WHOIS</div><div class="preview mono" style="font-family:monospace;font-size:10px;max-height:200px;overflow-y:auto">{esc(d["raw"][:500])}</div></div>'
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')


# ─────────────────────────────────────────────────────────────────
# TOOL: PORT SCAN
# ─────────────────────────────────────────────────────────────────
@router.get("/ports", response_class=HTMLResponse)
async def htmx_ports():
    return HTMLResponse("""<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Scan common TCP ports</div>
<div class="search-bar">
  <input id="ptd" name="domain" placeholder="Domain or IP" hx-post="/htmx/ports/scan" hx-target="#ptres" hx-trigger="keyup[key=='Enter']">
  <button hx-post="/htmx/ports/scan" hx-target="#ptres" hx-include="#ptd">Scan Ports</button>
</div>
<div id="ptres"></div>""")


@router.post("/ports/scan", response_class=HTMLResponse)
async def htmx_ports_scan(domain: str = Body("")):
    if not domain:
        return HTMLResponse('<div class="empty">Enter a domain or IP</div>')
    try:
        open_ports = port_scan(domain)
        html = f'<div class="card" style="margin-bottom:6px"><div class="title">🔌 Port Scan: {esc(domain)}</div><div class="meta">{len(open_ports)} ports open</div></div>'
        if open_ports:
            for p, n in open_ports:
                html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="title">{esc(n)} <span style="font-weight:400;color:#64748b">port {p}</span></div></div>'
        else:
            html += '<div class="empty">No common ports open</div>'
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')


# ─────────────────────────────────────────────────────────────────
# TOOL: HTTP CHECK
# ─────────────────────────────────────────────────────────────────
@router.get("/httpcheck", response_class=HTMLResponse)
async def htmx_httpcheck():
    return HTMLResponse("""<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Check HTTP/HTTPS response codes and SSL expiry</div>
<div class="search-bar">
  <input id="hcd" name="domain" placeholder="Domain" hx-post="/htmx/httpcheck/run" hx-target="#hcres" hx-trigger="keyup[key=='Enter']">
  <button hx-post="/htmx/httpcheck/run" hx-target="#hcres" hx-include="#hcd">Check</button>
</div>
<div id="hcres"></div>""")


@router.post("/httpcheck/run", response_class=HTMLResponse)
async def htmx_httpcheck_run(domain: str = Body("")):
    if not domain:
        return HTMLResponse('<div class="empty">Enter a domain</div>')
    try:
        http_s, https_s, ssl_d = http_check(domain)
        html = f'<div class="card" style="margin-bottom:6px"><div class="title">🌍 {esc(domain)}</div></div>'
        html += '<div class="details-grid">'
        if http_s:
            code = http_s.get("status_code")
            cls = "red" if code >= 400 else ("amber" if code >= 300 else "green")
            html += f'<span class="k">HTTP</span><span class="v {cls}">{code}</span>'
        if https_s:
            code = https_s.get("status_code")
            cls = "red" if code >= 400 else ("amber" if code >= 300 else "green")
            html += f'<span class="k">HTTPS</span><span class="v {cls}">{code}</span>'
        if ssl_d is not None:
            cls = "red" if ssl_d < 14 else ("amber" if ssl_d < 60 else "green")
            txt = "EXPIRED" if ssl_d < 0 else f"{ssl_d} days"
            html += f'<span class="k">SSL</span><span class="v {cls}">{txt}</span>'
        html += "</div>"
        if http_s and http_s.get("error"):
            html += f'<div class="card" style="margin-top:6px;border-color:#7f1d1d"><div class="preview" style="color:#f87171">HTTP error: {esc(http_s["error"])}</div></div>'
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')


# ─────────────────────────────────────────────────────────────────
# TOOL: SUBDOMAINS
# ─────────────────────────────────────────────────────────────────
@router.get("/subdomains", response_class=HTMLResponse)
async def htmx_subdomains():
    return HTMLResponse("""<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Enumerate common subdomains</div>
<div class="search-bar">
  <input id="sbd" name="domain" placeholder="Domain" hx-post="/htmx/subdomains/run" hx-target="#sbres" hx-trigger="keyup[key=='Enter']">
  <button hx-post="/htmx/subdomains/run" hx-target="#sbres" hx-include="#sbd">Enumerate</button>
</div>
<div id="sbres"></div>""")


@router.post("/subdomains/run", response_class=HTMLResponse)
async def htmx_subdomains_run(domain: str = Body("")):
    if not domain:
        return HTMLResponse('<div class="empty">Enter a domain</div>')
    try:
        subs = enum_subdomains(domain)
        html = f'<div class="card" style="margin-bottom:6px"><div class="title">🗂️ Subdomains: {esc(domain)}</div><div class="meta">{len(subs)} found</div></div>'
        if subs:
            for sd in subs:
                info = ", ".join(sd.get("ips",[])) if sd.get("ips") else (f'CNAME → {sd.get("cname","")}' if sd.get("cname") else "")
                html += f'<div class="card" style="padding:5px 10px;margin-bottom:2px"><div class="val mono">{esc(sd.get("subdomain",""))} → {esc(info)}</div></div>'
        else:
            html += '<div class="empty">No common subdomains found</div>'
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')


# ─────────────────────────────────────────────────────────────────
# TOOL: BLOCKLISTS
# ─────────────────────────────────────────────────────────────────
@router.get("/blocklists", response_class=HTMLResponse)
async def htmx_blocklists():
    return HTMLResponse("""<div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Check IP against DNS blocklists</div>
<div class="search-bar">
  <input id="bld" name="ip" placeholder="IP address" hx-post="/htmx/blocklists/check" hx-target="#blres" hx-trigger="keyup[key=='Enter']">
  <button hx-post="/htmx/blocklists/check" hx-target="#blres" hx-include="#bld">Check</button>
</div>
<div id="blres"></div>""")


@router.post("/blocklists/check", response_class=HTMLResponse)
async def htmx_blocklists_check(ip: str = Body("")):
    if not ip:
        return HTMLResponse('<div class="empty">Enter an IP address</div>')
    try:
        bl = check_blocklists(ip)
        html = f'<div class="card" style="margin-bottom:6px"><div class="title">🛡️ IP: {esc(ip)}</div></div>'
        if bl:
            for b in bl:
                cls = "red" if b.get("listed") else "green"
                html += f'<div class="card" style="padding:6px 10px;margin-bottom:2px"><div class="title">{esc(b.get("list",""))}</div><div class="val {cls}">{"LISTED ⚠" if b.get("listed") else "Clean ✓"}</div></div>'
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="empty">Error: {esc(str(e))}</div>')
