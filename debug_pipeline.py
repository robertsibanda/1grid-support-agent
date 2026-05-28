"""Debug pipeline step by step."""
import sys, json, time
sys.path.insert(0, ".")

from app.warehouse.queries import WarehouseDB
from app.rag.retriever import retrieve_context_structured
from app.zonewalk.runner import run_zonewalk
from app.agent.ollama_client import OllamaClient
import httpx
from app.config import settings

domain = "purify1.co.za"
issue = "WordPress 403"

# Step 1: Check Ollama
print("Step 1: Checking Ollama...")
try:
    r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=5)
    ollama_ok = r.status_code == 200
    print(f"  Ollama: {'connected' if ollama_ok else 'disconnected'}")
except Exception as e:
    ollama_ok = False
    print(f"  Ollama error: {e}")

# Step 2: Zonewalk
print("Step 2: Zonewalk...")
t0 = time.time()
z = run_zonewalk(domain)
print(f"  Done in {time.time()-t0:.1f}s — {'OK' if z['success'] else 'FAIL'}")

# Step 3: Warehouse
print("Step 3: Warehouse...")
w = WarehouseDB()
issues = w.search_issues(domain)
print(f"  {len(issues)} issues found")

# Step 4: KB
print("Step 4: KB search...")
kb_hits = retrieve_context_structured(f"{domain} {issue}", n_results=4)
print(f"  {len(kb_hits)} KB articles")

# Step 5: Ollama diagnosis
if ollama_ok:
    print("Step 5: Ollama diagnosis...")
    oc = OllamaClient()
    kb_text = "\n\n".join([f"--- {h['metadata'].get('title','')} ---\n{h['content'][:500]}" for h in kb_hits]) if kb_hits else ""
    warehouse_text = json.dumps({"issues": issues[:3]}, indent=2) if issues else "No history"
    zw_text = z.get("stdout", "")[:2000]
    
    t0 = time.time()
    import asyncio
    diagnosis = asyncio.run(oc.diagnose(domain, issue, zw_text, kb_text, warehouse_text))
    print(f"  Diagnosis done in {time.time()-t0:.1f}s")
    print(f"  Confidence: {diagnosis.get('confidence')}")
    print(f"  Response preview: {diagnosis.get('raw_response','')[:500]}")
else:
    print("Step 5: Skipped (no Ollama)")

print("\nAll steps completed")
