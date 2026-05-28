"""
1-grid AI Support Chatbot
Interactive CLI chatbot with RAG pipeline.

Usage:
  python chatbot.py                    # Interactive REPL mode
  python chatbot.py --domain example.com --issue "not receiving email"   # One-shot

Requires Ollama for AI responses. Without Ollama, runs in KB-only mode.
"""

import sys
import json
import argparse
from pathlib import Path

from app.config import settings
from app.warehouse.queries import WarehouseDB
from app.rag.retriever import retrieve_context_structured
from app.zonewalk.runner import run_zonewalk

warehouse = WarehouseDB()

SYSTEM_PROMPT = """You are Robert Sibanda, an ATS Support Agent at 1-grid South Africa.
First-line support: verify hosting, diagnose DNS/mail, initial triage.
Keep responses brief, professional, and informative.
Verify SPF/DKIM/DMARC/MX records.
Exhaust ALL L1 options before escalating."""

def check_ollama():
    import httpx
    try:
        r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3)
        return r.status_code == 200
    except:
        return False

def diagnose_with_ollama(domain, issue, zonewalk_output, kb_context, warehouse_history):
    import httpx
    prompt = f"""Domain: {domain}
Issue reported: {issue}

=== ZONEWALK OUTPUT ===
{zonewalk_output}

=== KB CONTEXT ===
{kb_context}

=== WAREHOUSE HISTORY ===
{warehouse_history}

Analyze this support ticket. Provide:
1. ROOT_CAUSE: The underlying problem
2. CONFIDENCE: High / Medium / Low
3. DRAFT_RESPONSE: Complete response for the customer
4. ACTIONS_TAKEN: Steps taken during diagnosis
5. ESCALATION: Yes/No"""

    body = {
        "model": settings.ollama_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "stream": False,
        "temperature": 0.1
    }
    r = httpx.post(f"{settings.ollama_url}/api/chat", json=body, timeout=120)
    return r.json()["message"]["content"]

def diagnose_db_only(domain, issue):
    lines = []
    lines.append(f"=== Diagnosis for {domain} ===")
    lines.append(f"Issue: {issue}")
    lines.append("")

    issues = warehouse.search_issues(domain)
    if issues:
        lines.append("Warehouse History:")
        for i in issues[:5]:
            lines.append(f"  #{i['id']} [{i['status']}] {i['issue_type']}: {i.get('issue_summary','')[:200]}")
    else:
        lines.append("Warehouse History: None found")

    client = warehouse.search_client(domain)
    if client:
        lines.append(f"Client: {client[0].get('name','')} ({client[0].get('email','')})")

    canned = warehouse.get_canned_response("")
    if canned:
        lines.append(f"\nCanned responses available: {len(canned)}")

    kb_hits = retrieve_context_structured(f"{domain} {issue}", n_results=3)
    if kb_hits:
        lines.append(f"\nRelevant KB articles ({len(kb_hits)}):")
        for h in kb_hits:
            lines.append(f"  - {h['metadata'].get('title','')}")

    lines.append(f"\nNote: Install Ollama (ollama.com/download) and pull {settings.ollama_model}")
    lines.append("for full AI-powered diagnosis with draft responses.")
    return "\n".join(lines)

def process_query(domain, issue):
    print(f"\n{'='*60}")
    print(f" Domain: {domain}")
    print(f" Issue:  {issue}")
    print(f"{'='*60}")

    print("\n[1/4] Running zonewalk...")
    z = run_zonewalk(domain)
    zonewalk_text = z.get("stdout", "") or z.get("error", "Not available on this machine")

    print("[2/4] Checking warehouse DB...")
    issues = warehouse.search_issues(domain)
    client = warehouse.search_client(domain)
    warehouse_text = json.dumps({"issues": issues[:3], "clients": client[:1]}, indent=2) if issues or client else "No history found"

    print("[3/4] Searching KB...")
    kb_hits = retrieve_context_structured(f"{domain} {issue}", n_results=4)
    kb_text = "\n\n".join([f"--- {h['metadata'].get('title','')} ---\n{h['content'][:500]}" for h in kb_hits]) if kb_hits else ""

    print("[4/4] Running diagnosis...")
    ollama_ok = check_ollama()
    print(f" Ollama: {'connected' if ollama_ok else 'not available'}")

    if ollama_ok:
        response = diagnose_with_ollama(domain, issue, zonewalk_text, kb_text, warehouse_text)
    else:
        response = diagnose_db_only(domain, issue)

    print(f"\n{'='*60}")
    print(" DIAGNOSIS RESULT")
    print(f"{'='*60}")
    print(response)
    print(f"\n{'='*60}")

    return response

def repl():
    print("\n" + "="*60)
    print("  1-grid AI Support Chatbot")
    print("="*60)
    print()
    print("Type a domain issue (e.g. 'check example.co.za no email')")
    print("Commands: /history <domain>, /kb <query>, /canned <topic>, /quickref <q>, /client <q>, /servers, /help, /quit")
    print()

    ollama_ok = check_ollama()
    if ollama_ok:
        print(f"  Ollama: connected ({settings.ollama_model})")
    else:
        print(f"  Ollama: not connected — KB/DB mode only")
        print(f"  Install: https://ollama.com/download")
        print(f"  Then: ollama pull {settings.ollama_model}")
    print()

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not line:
            continue

        if line == "/quit" or line == "/exit":
            print("Goodbye.")
            break

        if line == "/help":
            print("Commands:")
            print("  <domain> <issue>     Diagnose a domain issue")
            print("  /history <domain>    Lookup domain history")
            print("  /kb <query>          Search KB articles")
            print("  /canned <topic>      Find canned responses")
            print("  /quickref <query>    Lookup quick reference")
            print("  /servers             List known servers")
            print("  /client <domain>     Lookup client info")
            print("  /status              Show system status")
            print("  /quit                Exit")
            continue

        if line == "/status":
            print(f"  Ollama: {'connected' if check_ollama() else 'disconnected'}")
            print(f"  Model:  {settings.ollama_model}")
            print(f"  DB:     {settings.warehouse_db}")
            print(f"  KB:     {len(retrieve_context_structured('test', 10))} articles indexed")
            continue

        if line.startswith("/history "):
            domain = line[9:].strip()
            issues = warehouse.search_issues(domain)
            if issues:
                for i in issues:
                    print(f"  #{i['id']} [{i['status']}] {i['issue_type']} - {i.get('issue_summary','')[:200]}")
            else:
                print(f"  No history for {domain}")
            continue

        if line.startswith("/kb "):
            query = line[4:].strip()
            hits = retrieve_context_structured(query, 5)
            if hits:
                for h in hits:
                    print(f"  - {h['metadata'].get('title','')} (dist: {h.get('distance',0):.3f})")
            else:
                print("  No results")
            continue

        if line.startswith("/canned "):
            topic = line[8:].strip()
            resp = warehouse.get_canned_response(topic)
            if resp:
                for r in resp:
                    print(f"  [{r['title']}]")
                    print(f"  {r['response_body'][:300]}...")
            else:
                print(f"  No canned responses for '{topic}'")
            continue

        if line.startswith("/quickref "):
            query = line[10:].strip()
            refs = warehouse.get_quick_ref(query)
            if refs:
                for r in refs:
                    print(f"  [{r['category']}] {r['key_name']}: {r['value'][:200]}")
            else:
                print(f"  No quick reference for '{query}'")
            continue

        if line.startswith("/client "):
            query = line[8:].strip()
            clients = warehouse.search_client(query)
            if clients:
                for c in clients:
                    dm = c.get('domains_managed') or ''
                    print(f"  {c.get('name','')} ({c.get('email','')}) - {dm[:80]}")
            else:
                print(f"  No client found for '{query}'")
            continue

        if line == "/servers":
            servers = warehouse.get_server()
            if servers:
                for s in servers:
                    ki = s.get('known_issues') or 'none'
                    print(f"  {s['hostname']} ({s['ip']}) - {s.get('hosting_type','')} - {ki[:100]}")
            else:
                print("  No servers found")
            continue

        parts = line.split(" ", 1)
        domain = parts[0].strip()
        issue = parts[1].strip() if len(parts) > 1 else "General inquiry"

        if not domain or not "." in domain:
            print("  Usage: <domain.tld> <issue description>")
            print("  e.g.:  example.co.za not receiving email")
            continue

        process_query(domain, issue)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="1-grid AI Support Chatbot")
    parser.add_argument("--domain", help="Domain to diagnose")
    parser.add_argument("--issue", help="Issue description", default="")
    args = parser.parse_args()

    if args.domain:
        process_query(args.domain, args.issue or "General inquiry")
    else:
        repl()
