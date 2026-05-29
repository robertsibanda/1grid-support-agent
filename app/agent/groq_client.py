import json
import logging
import httpx
from app.config import settings

logger = logging.getLogger(__name__)

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

AVAILABLE COMMANDS (quick reference):
Server commands:
- DKIM Install: /usr/local/cpanel/bin/dkim_keys_install && /scripts/buildeximconf
- Rebuild Exim: /usr/local/cpanel/scripts/buildeximconf && service exim restart && service dovecot restart
- Dovecot restart: systemctl restart dovecot
- Dovecot who: doveadm who
- Dovecot force resync: doveadm force-resync -u <email> INBOX
- Dovecot live sync: doveadm -D sync -u <user> tcp:<storage-server>:12345
- Reverse sync: python2 /root/sysadmin/dovecot-sync/migrate-mailbox.py -R <email>
- Delete old queue: exiqgrep -o 3600 -i | xargs exim -Mrm
- Unsuspend SMTP: whmapi1 unsuspend_outgoing_email user=$(/scripts/whoowns <domain>) email=<email>
- Suspend SMTP: whmapi1 suspend_outgoing_email user=$(/scripts/whoowns <domain>) email=<email>
- Postfix/Mailchannels flush: scan mailq for refused Mailchannels, requeue
- Fix file perms: find . -type f -exec chmod 644 {} + && find . -type d -exec chmod 755 {} +
- Chown mail dir: chown -R <user>:<group> /home/<user>/mail/<domain>/
- Apache check: apachectl fullstatus / grep MaxRequestWorkers
- MailStorage perm reset: /scripts/mailstorage_cpresetperms.sh <server> <mailbox>

Teleport:
- Install: curl + yum install teleport-17.3.0-1.x86_64.rpm
- Config: /etc/teleport.yaml with auth_server teleport.hostserv.co.za:3025
- Uninstall: systemctl stop teleport && pkill -f teleport && rm -rf /var/lib/teleport
- CSF allow: add 41.61.20.124:3025 to csf.conf

Archive:
- Search: ls -al /mnt/data/home/*/cancelled_archive/<file>
- Restore: rsync from /mnt/data/home/<server>/cancelled_archive/ to target

Security:
- Block all countries except ZA: MaxMindDB GeoIP in Apache config
- Hacklink malware: grep -rl "hacklinkmarket\|wp_core_check" /home/*/public_html/
- Microsoft delisting: https://olcsupport.office.com/
- Block country in Apache: MaxMindDB + IfModule

SOP:
- Log template: Channel, Ticket #, Domain, Server IP, PTR, Category, Sub-category, Description, Outcome
- Freshdesk ticket: always log with format above

CONTEXT:
- Mail servers: winsvrmail07.hostserv.co.za (41.185.110.26)
- Nameservers: ns1.hostserv.co.za, ns2.hostserv.co.za
- Standard SPF: v=spf1 a mx include:relay.mailchannels.net ~all
- OpenProvider: 1-grid's reseller registrar for .com TLDs
- Roundcube repair: mysqlcheck -r roundcube
- SELinux fix: setenforce 0
- Catch spammers: catch_spammers.sh

If high confidence in diagnosis, return a draft response for the customer.
If uncertain, flag for human review."""

class GroqClient:
    def __init__(self):
        self.api_key = settings.groq_api_key
        self.model = settings.groq_model
        self.base_url = "https://api.groq.com/openai/v1"
        self.timeout = 120

    async def chat_stream(self, messages: list[dict], temperature: float = 0.1):
        if not self.api_key:
            raise RuntimeError("Groq API key not configured")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
            "stream": True,
            "temperature": temperature,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream("POST", f"{self.base_url}/chat/completions", json=payload, headers=headers) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line or line == "data: [DONE]":
                        continue
                    if line.startswith("data: "):
                        try:
                            data = json.loads(line[6:])
                            choices = data.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    yield content
                        except json.JSONDecodeError:
                            continue

    async def chat(self, messages: list[dict], temperature: float = 0.1) -> str:
        if not self.api_key:
            raise RuntimeError("Groq API key not configured")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
            "stream": False,
            "temperature": temperature,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def diagnose(self, domain: str, issue: str, zonewalk_output: str,
                       kb_context: str, warehouse_history: str) -> dict:
        messages = [{
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
        }]
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
