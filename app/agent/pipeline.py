import json
import logging
from datetime import datetime
from app.agent.ollama_client import OllamaClient
from app.agent.groq_client import GroqClient
from app.rag.retriever import retrieve_context
from app.warehouse.queries import WarehouseDB
from app.zonewalk.runner import run_zonewalk
from app.config import settings

logger = logging.getLogger(__name__)

class SupportPipeline:
    def __init__(self):
        self.ollama = OllamaClient()
        self.groq = GroqClient()
        self.warehouse = WarehouseDB()
        self.use_groq = bool(settings.groq_api_key)
        if self.use_groq:
            logger.info(f"Using Groq API (model: {settings.groq_model})")
        else:
            logger.info("No Groq API key — falling back to local Ollama")

    async def process_ticket(self, domain: str, issue: str,
                             ticket_id: str = None, customer_email: str = None) -> dict:
        steps = []

        steps.append({"step": "zonewalk", "status": "running"})
        zonewalk_result = run_zonewalk(domain)
        steps[-1]["status"] = "done" if zonewalk_result["success"] else "failed"
        steps[-1]["output"] = zonewalk_result.get("stdout", "")[:2000]

        steps.append({"step": "warehouse_check", "status": "running"})
        warehouse_history = ""
        try:
            domain_issues = self.warehouse.search_issues(domain)
            if domain_issues:
                warehouse_history = json.dumps(domain_issues, indent=2)
            server_info = self.warehouse.get_server(hostname="")
            steps[-1]["status"] = "done"
        except Exception as e:
            steps[-1]["status"] = "failed"
            steps[-1]["error"] = str(e)

        steps.append({"step": "kb_retrieval", "status": "running"})
        try:
            kb_context = retrieve_context(f"{domain} {issue}")
            steps[-1]["status"] = "done"
            steps[-1]["matches"] = len(kb_context) if kb_context else 0
        except Exception as e:
            kb_context = ""
            steps[-1]["status"] = "failed"
            steps[-1]["error"] = str(e)

        steps.append({"step": "model_diagnosis", "status": "running"})
        try:
            llm = self.groq if self.use_groq else self.ollama
            diagnosis = await llm.diagnose(
                domain=domain,
                issue=issue,
                zonewalk_output=zonewalk_result.get("stdout", ""),
                kb_context=kb_context,
                warehouse_history=warehouse_history
            )
            steps[-1]["status"] = "done"
        except Exception as e:
            diagnosis = {
                "domain": domain,
                "raw_response": f"Error during model diagnosis: {str(e)}",
                "confidence": "Low",
                "needs_escalation": True,
                "model": settings.groq_model if self.use_groq else settings.ollama_model
            }
            steps[-1]["status"] = "failed"
            steps[-1]["error"] = str(e)

        auto_send = diagnosis["confidence"] == "High"
        needs_review = diagnosis["confidence"] in ("Medium", "Low") or diagnosis["needs_escalation"]

        result = {
            "ticket_id": ticket_id,
            "domain": domain,
            "issue": issue,
            "customer_email": customer_email,
            "diagnosis": diagnosis,
            "steps": steps,
            "auto_send": auto_send,
            "needs_review": needs_review,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        await self._log_exchange(domain, issue, result)

        return result

    async def _log_exchange(self, domain: str, issue: str, result: dict):
        try:
            entry = {
                "id": f"ticket_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source": "ai-support-agent",
                "cli": "pipeline",
                "domain": domain,
                "issue": issue,
                "messages": [
                    {"role": "user", "content": f"Domain: {domain}, Issue: {issue}"},
                    {"role": "assistant", "content": result["diagnosis"]["raw_response"]}
                ],
                "commands": [
                    {"step": s["step"], "status": s.get("status"), "output": s.get("output", "")[:500]}
                    for s in result["steps"]
                ]
            }
            with open(settings.conversations_jsonl, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.warning(f"Failed to log exchange: {e}")

    async def quick_diagnose(self, domain: str, issue: str = "") -> dict:
        zonewalk_result = run_zonewalk(domain)
        kb_context = retrieve_context(f"{domain} {issue}")

        llm = self.groq if self.use_groq else self.ollama
        diagnosis = await llm.diagnose(
            domain=domain,
            issue=issue or "General inquiry",
            zonewalk_output=zonewalk_result.get("stdout", ""),
            kb_context=kb_context,
            warehouse_history=""
        )

        return {
            "domain": domain,
            "zonewalk": {
                "success": zonewalk_result["success"],
                "summary": zonewalk_result.get("stdout", "")[:1000]
            },
            "diagnosis": diagnosis,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
