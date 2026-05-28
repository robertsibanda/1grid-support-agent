import httpx
from app.config import settings

SYSTEM_PROMPT = """You are Robert Sibanda, an ATS Support Agent at 1-grid South Africa.

ROLE:
- First-line support: verify hosting, diagnose DNS/mail, initial triage, customer communication
- Escalate to L2/L3 for server-level changes or deep investigations

WORKFLOW:
1. For any domain query, run zonewalk first for comprehensive view
2. Check warehouse DB for domain history
3. Search KB for relevant articles
4. Keep responses short, professional, and informative
5. Always verify SPF/DKIM/DMARC/MX records
6. Exhaust ALL L1 options before escalating

RESPONSE STYLE:
- Informative, educative, sincere, warm, professional
- Brief and direct — under 3 second turnaround target
- Include zonewalk findings in structured format

CONTEXT:
- Mail servers: winsvrmail07.hostserv.co.za (41.185.110.26)
- Nameservers: ns1.hostserv.co.za, ns2.hostserv.co.za
- Standard SPF: v=spf1 a mx include:relay.mailchannels.net ~all

If high confidence in diagnosis, return a draft response for the customer.
If uncertain, flag for human review."""

class OllamaClient:
    def __init__(self):
        self.base_url = settings.ollama_url.rstrip("/")
        self.model = settings.ollama_model

    async def chat(self, messages: list[dict], temperature: float = 0.1) -> str:
        async with httpx.AsyncClient(timeout=120) as client:
            payload = {
                "model": self.model,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
                "stream": False,
                "temperature": temperature,
            }
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]

    async def diagnose(self, domain: str, issue: str, zonewalk_output: str,
                       kb_context: str, warehouse_history: str) -> dict:
        messages = [
            {
                "role": "user",
                "content": (
                    f"Domain: {domain}\n"
                    f"Issue reported: {issue}\n\n"
                    f"=== ZONEWALK OUTPUT ===\n{zonewalk_output}\n\n"
                    f"=== KB CONTEXT ===\n{kb_context}\n\n"
                    f"=== WAREHOUSE HISTORY ===\n{warehouse_history}\n\n"
                    "Analyze the issue and provide:\n"
                    "1. ROOT_CAUSE: What is the underlying problem?\n"
                    "2. CONFIDENCE: High / Medium / Low\n"
                    "3. DRAFT_RESPONSE: A complete response ready to send to the customer\n"
                    "4. ACTIONS_TAKEN: What was done during diagnosis\n"
                    "5. ESCALATION: Whether this needs L2/L3 escalation"
                )
            }
        ]

        response = await self.chat(messages)

        confidence = "Low"
        if "CONFIDENCE: High" in response:
            confidence = "High"
        elif "CONFIDENCE: Medium" in response:
            confidence = "Medium"

        needs_escalation = "ESCALATION: Yes" in response or "ESCALATION: L2" in response or "ESCALATION: L3" in response

        return {
            "domain": domain,
            "raw_response": response,
            "confidence": confidence,
            "needs_escalation": needs_escalation,
            "model": self.model
        }

    async def generate_canned_response(self, ticket_type: str, details: str) -> str:
        messages = [
            {
                "role": "user",
                "content": (
                    f"Generate a professional canned response for a {ticket_type} ticket.\n"
                    f"Details: {details}\n\n"
                    "Make it warm, informative, and include next steps for the customer."
                )
            }
        ]
        return await self.chat(messages, temperature=0.3)
