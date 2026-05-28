import json
from datetime import datetime
from app.rag.chroma_client import ChromaService

KB_ARTICLES = [
    {
        "id": "kb_email_settings",
        "title": "Email Settings for Devices",
        "content": (
            "Recommended server settings for 1-grid email accounts:\n"
            "SMTP Server: mail.yourdomain.co.za\n"
            "SMTP Port TLS: 587\n"
            "SMTP Port SSL: 465\n"
            "IMAP/POP3: Use mail.yourdomain.co.za\n"
            "Authentication: Required - full email address\n"
            "Outgoing server requires authentication: Yes"
        ),
        "category": "email",
        "source": "https://1grid.co.za/knowledge/settings-to-configure-your-1grid-email-accounts-across-devices/"
    },
    {
        "id": "kb_email_troubleshooting",
        "title": "Basic Email Troubleshooting",
        "content": (
            "Basic troubleshooting steps for email issues:\n"
            "1. Verify DNS records (MX, SPF, DKIM, DMARC)\n"
            "2. Check mail queue with exim -bp\n"
            "3. Verify domain is in localdomains or remotedomains\n"
            "4. Test routing with exim -bt email@domain.com\n"
            "5. Check SpamTitan quarantine\n"
            "6. Verify MailChannels delivery\n"
            "7. Check mail storage with doveadm"
        ),
        "category": "email",
        "source": "https://1grid.co.za/knowledge/troubleshooting-steps-for-email/"
    },
    {
        "id": "kb_smtp_451",
        "title": "SMTP Error 451",
        "content": (
            "SMTP Error 451: Temporary local problem - How to fix:\n"
            "Cause: Temporary issue on mail server (resource pressure, queue backup, or DNS issue)\n"
            "Resolution:\n"
            "1. Check exim queue: exim -bp | exiqsumm\n"
            "2. Check disk space: df -h\n"
            "3. Check load: uptime\n"
            "4. Restart exim: /scripts/buildeximconf && service exim restart\n"
            "5. If MailChannels timeout: check smtp.mailchannels.net connectivity"
        ),
        "category": "email",
        "source": "https://1grid.co.za/knowledge/smtp-error-451-temporary-local-problem-how-to-fix/"
    },
    {
        "id": "kb_smtp_550",
        "title": "SMTP Error 550",
        "content": (
            "SMTP Error 550: Message rejected by server - How to fix:\n"
            "Cause: Receiver rejecting mail (SPF fail, IP blacklisted, content flagged)\n"
            "Resolution:\n"
            "1. Verify SPF record includes relay.mailchannels.net\n"
            "2. Check IP reputation via zonewalk --ip-reputation\n"
            "3. Check if IP is on any blacklists\n"
            "4. Verify DKIM is properly set up\n"
            "5. Microsoft delisting: https://sender.office.com"
        ),
        "category": "email",
        "source": "https://1grid.co.za/knowledge/smtp-error-550-message-rejected-by-server-how-to-fix-it/"
    },
    {
        "id": "kb_spf_records",
        "title": "Standard SPF Records",
        "content": (
            "Standard SPF records for 1-grid hosting:\n"
            "Shared hosting: v=spf1 a mx include:relay.mailchannels.net ~all\n"
            "CVPS: v=spf1 +ip4:<server_ip> include:relay.mailchannels.net ~all\n"
            "Always verify with: host -t txt domain myserver.ns.1-grid.com\n"
            "Note: Missing +ip4: on CVPS causes send failures"
        ),
        "category": "dns",
        "source": "internal"
    },
    {
        "id": "kb_dmarc_record",
        "title": "Standard DMARC Records",
        "content": (
            "Standard DMARC record for 1-grid hosting:\n"
            "Host: _dmarc\n"
            "Value: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.co.za\n"
            "Replace yourdomain.co.za with actual domain to receive reports"
        ),
        "category": "dns",
        "source": "internal"
    },
    {
        "id": "kb_nameservers",
        "title": "1-grid Nameservers",
        "content": (
            "Standard 1-grid nameservers by hosting type:\n"
            "Windows Plesk: petra.ns.1-grid.com (.co.uk, .co.za, .net)\n"
            "Linux Plesk: thor.ns.1-grid.com (.co.uk, .co.za, .net)\n"
            "Linux cPanel (1): linus.ns.1-grid.com (.co.uk, .co.za, .net)\n"
            "Linux cPanel (2): ns1.hostserv.co.za, ns2.hostserv.co.za\n"
            "Business VPS: myserver.ns.1-grid.com (.co.uk, .co.za, .net)\n"
            "If customer uses private nameservers (ns1.my-server.co.za): reseller setup"
        ),
        "category": "dns",
        "source": "internal"
    },
    {
        "id": "kb_mail_flow",
        "title": "1-grid Mail Flow",
        "content": (
            "1-grid mail flow:\n"
            "Internal (1-grid to 1-grid): Delivered server-to-server. Bypasses SpamTitan and MailChannels.\n"
            "Inbound (External to 1-grid): Scanned by SpamTitan first, then delivered to mailbox.\n"
            "Outbound (1-grid to External): Routed through MailChannels for spam filtering, then delivered.\n"
            "Compromised accounts can spam other 1-grid customers without filters catching it."
        ),
        "category": "email",
        "source": "internal"
    },
    {
        "id": "kb_modsecurity",
        "title": "ModSecurity Rules (Windows Plesk)",
        "content": (
            "Known ModSecurity OWASP CRS 4.25.0 rules blocking WordPress:\n"
            "Rule 942200 - blocks %2C in query strings (_fields param)\n"
            "Rule 921110 - blocks X-HTTP-Method* headers (request smuggling prevention)\n"
            "Fix: Plesk > WAF > Add exception for rule ID + path regex /wp-json/.*"
        ),
        "category": "security",
        "source": "internal"
    },
    {
        "id": "kb_server_hold",
        "title": "ServerHold Status",
        "content": (
            "ServerHold domain status:\n"
            "Prevents nameserver changes\n"
            "Check: whois domain | grep -i 'Domain Status' | grep serverHold\n"
            "Fix: billing department must release the hold"
        ),
        "category": "domains",
        "source": "internal"
    },
    {
        "id": "kb_openprovider",
        "title": "OpenProvider = 1-grid (.com TLDs)",
        "content": (
            "OpenProvider / Hosting Concepts B.V. d/b/a Registrar.eu is 1-grid's reseller registrar for .com TLDs.\n"
            "Do NOT treat as third-party registration when WHOIS shows this."
        ),
        "category": "domains",
        "source": "internal"
    },
    {
        "id": "kb_chapman_spam",
        "title": "Known Spammer: Chapman Skills / AshWeb",
        "content": (
            "KNOWN SPAMMER: Chapman Skills / AshWeb - POPIA Spam Complaint\n"
            "Domains: chapmanskills.co.za (srv147), ashweb.co.za (srv99)\n"
            "Pattern: Creates new domains repeatedly, spamming since 2022\n"
            "Action on appearance: Suspend outgoing mail and account immediately\n"
            "Escalate to Abuse team for permanent termination if non-compliant"
        ),
        "category": "security",
        "source": "internal"
    },
    {
        "id": "kb_mailchannels_timeout",
        "title": "MailChannels/Exim Timeout",
        "content": (
            "MailChannels/Exim timeout issue:\n"
            "Error: retry timeout exceeded at smtp.mailchannels.net\n"
            "Affected servers: srv05, srv07, srv19, srv53, srv63, srv66, srv78, srv81, srv109, srv144, srv172, and CVPS servers\n"
            "Resolution: SysOps deploys config fix. Some servers need Exim restart post-fix.\n"
            "Standard response includes: 'Apologies for the inconvenience caused'"
        ),
        "category": "email",
        "source": "internal"
    },
    {
        "id": "kb_plesk_email_password",
        "title": "Plesk Email Password Lookup",
        "content": (
            "Plesk email password lookup:\n"
            "All: /usr/local/psa/admin/bin/mail_auth_view\n"
            "By domain: /usr/local/psa/admin/bin/mail_auth_view | grep domain\n"
            "Plesk DB queries also available via: plesk db"
        ),
        "category": "email",
        "source": "internal"
    },
    {
        "id": "kb_acronis_restart",
        "title": "Acronis Restart Commands",
        "content": (
            "Acronis backup plugin restart:\n"
            "systemctl restart acronis_plugin\n"
            "systemctl restart acronis_mms\n"
            "systemctl restart aakore\n"
            "If persists: contact Acronis Support"
        ),
        "category": "backup",
        "source": "internal"
    },
    {
        "id": "kb_csf_firewall",
        "title": "CSF Firewall Commands",
        "content": (
            "CSF firewall quick reference:\n"
            "Check IP: csf -g ip\n"
            "Remove block: csf -dr ip\n"
            "Temp allow: csf -ta ip 24h\n"
            "Permanent allow: csf -a ip\n"
            "Restart: csf -r\n"
            "Disable: csf -x\n"
            "Enable: csf -e"
        ),
        "category": "security",
        "source": "internal"
    },
    {
        "id": "kb_bitninja",
        "title": "BitNinja Commands",
        "content": (
            "BitNinja security commands:\n"
            "Remove from greylist: bitninjacli --greylist --del=IP\n"
            "Add to whitelist: bitninjacli --whitelist --add=IP\n"
            "Check blacklist: bitninjacli --blacklist --check=IP\n"
            "Restart: systemctl restart bitninja"
        ),
        "category": "security",
        "source": "internal"
    },
    {
        "id": "kb_vps_packages",
        "title": "VPS Package Codes",
        "content": (
            "VPS package upgrade path:\n"
            "STARTER(STARTER/TINY) -> STANDARD(Small) -> PREMIUM(Medium) -> PREMIUMPLUS(Large) -> ULTIMATE(XL)\n"
            "OS Linux: CENTOS65, CENTOS70, CENTOS80, UBUNTU1204, UBUNTU1310, UBUNTU1404, UBUNTU1604, UBUNTU2004\n"
            "OS Windows: WIN08R2STD, WIN08R2WEB, WIN12R2STD, WIN12STD, WIN16STD, WIN19STD\n"
            "SATA Addon: SATA50, SATA100, SATA200, SATA300, 512000"
        ),
        "category": "hosting",
        "source": "internal"
    },
]

def ingest_all_kb():
    chroma = ChromaService()
    collection = chroma.get_or_create_collection("kb_articles")

    existing_ids = set()
    existing = collection.get()
    if existing["ids"]:
        existing_ids = set(existing["ids"])

    documents = []
    metadatas = []
    ids = []

    for article in KB_ARTICLES:
        if article["id"] in existing_ids:
            continue
        documents.append(f"# {article['title']}\n\n{article['content']}")
        metadatas.append({
            "title": article["title"],
            "category": article["category"],
            "source": article["source"]
        })
        ids.append(article["id"])

    if documents:
        collection.add(documents=documents, metadatas=metadatas, ids=ids)

    return {"ingested": len(documents), "total": len(KB_ARTICLES)}

def ingest_from_warehouse(db_path: str):
    import sqlite3
    chroma = ChromaService()
    collection = chroma.get_or_create_collection("kb_articles")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("SELECT id, question, answer, category FROM qa_log").fetchall()
    conn.close()

    documents = []
    metadatas = []
    ids = []

    for row in rows:
        doc_id = f"qa_{row['id']}"
        documents.append(f"Q: {row['question']}\nA: {row['answer']}")
        metadatas.append({
            "title": row["question"][:100],
            "category": row["category"] or "qa",
            "source": "warehouse_db"
        })
        ids.append(doc_id)

    if documents:
        collection.add(documents=documents, metadatas=metadatas, ids=ids)

    return {"ingested_qa": len(documents)}

if __name__ == "__main__":
    result = ingest_all_kb()
    print(f"Ingested {result['ingested']} new articles ({result['total']} total)")
