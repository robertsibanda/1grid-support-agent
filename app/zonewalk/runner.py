"""
Python-native zonewalk: DNS, mail auth, web, port, and reputation checks.
Replaces zonewalk.sh with cross-platform Python implementation.
"""

import asyncio
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import httpx

# ── Config ──────────────────────────────────────────────────────────────
GRID_NS_PATTERNS = {
    "petra": "Windows Plesk",
    "thor": "Linux Plesk",
    "linus": "Linux cPanel (1)",
    "hostserv": "Linux cPanel (2)",
    "lnxwzdns": "Website Design",
    "myserver": "Business VPS",
    "openprovider": "OpenProvider",
}
COMPETITORS = [
    ("cloudflare", "Cloudflare"),
    ("hetzner", "Hetzner/xneelo"),
    ("xneelo", "xneelo"),
    ("hostafrica", "Host Africa"),
    ("afrihost", "Afrihost"),
    ("google", "Google Workspace"),
    ("outlook", "Microsoft 365"),
    ("amazonaws", "AWS Route53"),
    ("azure", "Azure DNS"),
    ("godaddy", "GoDaddy"),
    ("namecheap", "Namecheap"),
]
COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "imap", "pop", "pop3",
    "ftp", "cpanel", "whm", "plesk", "ns1", "ns2", "dev",
    "staging", "api", "admin", "portal", "secure", "vpn",
    "autodiscover", "autoconfig", "calendar", "contacts",
    "webdisk", "cpcalendars", "cpcontacts",
]
COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (443, "HTTPS"),
    (465, "SMTPS"), (587, "SMTP-Submission"), (993, "IMAPS"),
    (995, "POP3S"), (2083, "cPanel"), (2087, "WHM"),
    (3306, "MySQL"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
]
BLACKLISTS = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    ("psbl.surriel.com", "PSBL"),
]
DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "mail",
    "dkim", "k1", "zoho", "s1", "s2", "smtp", "email", "mimecast",
]
RESOLVERS_PROPS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("OpenDNS", "208.67.220.220"),
    ("Liquid ZA", "154.0.1.1"),
    ("Telkom ZA", "196.25.1.1"),
    ("Google (SA)", "8.8.4.4"),
]

class Resolver:
    """Unified DNS resolver wrapper."""
    def __init__(self, timeout: float = 5.0):
        self._resolver = dns.resolver.Resolver(configure=True)
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        self.timeout = timeout

    def _resolve(self, qname: str, rdtype: str, nameserver: str = None) -> list[str]:
        try:
            r = dns.resolver.Resolver(configure=True)
            r.timeout = self.timeout
            r.lifetime = self.timeout
            if nameserver:
                r.nameservers = [nameserver]
            answers = r.resolve(qname, rdtype, raise_on_no_answer=False)
            return [str(a) for a in answers]
        except Exception:
            return []

    def a(self, domain: str, ns: str = None) -> list[str]:
        return self._resolve(domain, "A", ns)

    def aaaa(self, domain: str, ns: str = None) -> list[str]:
        return self._resolve(domain, "AAAA", ns)

    def ns(self, domain: str) -> list[str]:
        return self._resolve(domain, "NS")

    def mx(self, domain: str) -> list[tuple[int, str]]:
        try:
            answers = self._resolver.resolve(domain, "MX")
            return sorted([(int(a.preference), str(a.exchange).rstrip(".")) for a in answers])
        except Exception:
            return []

    def txt(self, domain: str) -> list[str]:
        return self._resolve(domain, "TXT")

    def soa(self, domain: str) -> Optional[dict]:
        try:
            a = self._resolver.resolve(domain, "SOA")[0]
            return {
                "mname": str(a.mname),
                "rname": str(a.rname),
                "serial": a.serial,
                "refresh": a.refresh,
                "retry": a.retry,
                "expire": a.expire,
                "minimum": a.minimum,
            }
        except Exception:
            return None

    def ptr(self, ip: str) -> Optional[str]:
        try:
            a = dns.reversename.from_address(ip)
            return str(self._resolver.resolve(a, "PTR")[0]).rstrip(".")
        except Exception:
            return None

    def cname(self, domain: str) -> Optional[str]:
        try:
            return str(self._resolver.resolve(domain, "CNAME")[0]).rstrip(".")
        except Exception:
            return None

    def resolve_ns(self, domain: str, ns: str) -> list[str]:
        """Resolve A record using specific nameserver."""
        return self._resolve(domain, "A", ns)


@dataclass
class ZonewalkResult:
    domain: str
    timestamp: str = ""
    nameservers: list[str] = field(default_factory=list)
    hosting_provider: str = ""
    hosting_type: str = ""
    is_grid: bool = False
    whois: dict = field(default_factory=dict)
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    ptr_record: Optional[str] = None
    mx_records: list[tuple] = field(default_factory=list)
    spf_record: Optional[str] = None
    dkim_records: list[str] = field(default_factory=list)
    dmarc_record: Optional[str] = None
    has_mailchannels: bool = False
    soa: Optional[dict] = None
    http_status: Optional[dict] = None
    https_status: Optional[dict] = None
    ssl_expiry_days: Optional[int] = None
    open_ports: list[tuple] = field(default_factory=list)
    blocklists: list[dict] = field(default_factory=list)
    subdomains: list[dict] = field(default_factory=list)
    propagation: list[dict] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    success: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


def whois_lookup(domain: str, timeout: float = 10) -> dict:
    """Simple WHOIS lookup via whois.iana.org referral."""
    result = {"registrar": "", "expiry": "", "status": "", "raw": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("whois.iana.org", 43))
        sock.sendall(f"{domain}\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        text = data.decode("utf-8", errors="ignore")
        result["raw"] = text[:2000]

        for line in text.splitlines():
            l = line.lower()
            if "registrar:" in l and not result["registrar"]:
                result["registrar"] = line.split(":", 1)[1].strip()
            if "expir" in l and "date" in l:
                result["expiry"] = line.split(":", 1)[1].strip()
            if "status:" in l:
                result["status"] = (result["status"] + " " + line.split(":", 1)[1].strip()).strip()
    except Exception:
        pass
    return result


def port_scan(domain: str, ports: list[tuple[int, str]] = None, timeout: float = 3) -> list[tuple[int, str]]:
    """Scan TCP ports on domain/IP."""
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []

    def _check(p: int, name: str) -> Optional[tuple[int, str]]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((domain, p))
            s.close()
            if result == 0:
                return (p, name)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {ex.submit(_check, p, n): (p, n) for p, n in ports}
        for f in futures:
            r = f.result()
            if r:
                open_ports.append(r)
    return sorted(open_ports, key=lambda x: x[0])


def check_blocklists(ip: str, timeout: float = 3) -> list[dict]:
    """Check IP against DNS blocklists."""
    results = []
    try:
        rev = ".".join(reversed(ip.split(".")))
        for bl_host, bl_name in BLACKLISTS:
            try:
                a = dns.resolver.resolve(f"{rev}.{bl_host}", "A", lifetime=timeout)
                listed = any(str(r) for r in a)
                results.append({"list": bl_name, "listed": bool(listed)})
            except Exception:
                results.append({"list": bl_name, "listed": False})
    except Exception:
        pass
    return results


def http_check(domain: str, timeout: float = 10) -> tuple[Optional[dict], Optional[dict], Optional[int]]:
    """Check HTTP and HTTPS status."""
    http_status = None
    https_status = None
    ssl_days = None

    try:
        r = httpx.get(f"http://{domain}", timeout=timeout, follow_redirects=True)
        http_status = {"status_code": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        http_status = {"status_code": 0, "error": str(e)}

    try:
        r = httpx.get(f"https://{domain}", timeout=timeout, follow_redirects=True, verify=False)
        https_status = {"status_code": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        https_status = {"status_code": 0, "error": str(e)}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert and "notAfter" in cert:
                    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    ssl_days = (exp.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    except Exception:
        pass

    return http_status, https_status, ssl_days


def enum_subdomains(domain: str, timeout: float = 3) -> list[dict]:
    """Enumerate common subdomains."""
    found = []
    res = dns.resolver.Resolver(configure=True)
    res.timeout = timeout
    res.lifetime = timeout

    def _check(sub: str) -> Optional[dict]:
        try:
            target = f"{sub}.{domain}"
            a = res.resolve(target, "A", raise_on_no_answer=False)
            if a:
                ips = [str(r) for r in a]
                return {"subdomain": target, "ips": ips, "type": "A"}
        except dns.resolver.NoAnswer:
            pass
        except Exception:
            pass
        try:
            target = f"{sub}.{domain}"
            cname = res.resolve(target, "CNAME", raise_on_no_answer=False)
            if cname:
                return {"subdomain": target, "cname": str(cname[0]), "type": "CNAME"}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_check, s): s for s in COMMON_SUBDOMAINS}
        for f in futures:
            r = f.result()
            if r:
                found.append(r)
    return found


def check_propagation(domain: str, expected_ips: list[str], timeout: float = 3) -> list[dict]:
    """Check A record propagation across global resolvers."""
    results = []
    for name, ns_ip in RESOLVERS_PROPS:
        try:
            r = dns.resolver.Resolver(configure=True)
            r.timeout = timeout
            r.lifetime = timeout
            r.nameservers = [ns_ip]
            answers = r.resolve(domain, "A", raise_on_no_answer=False)
            ips = [str(a) for a in answers]
            match = any(ip in expected_ips for ip in ips) if ips else False
            results.append({"resolver": name, "ip": ns_ip, "result": ips, "match": match})
        except Exception as e:
            results.append({"resolver": name, "ip": ns_ip, "result": [], "match": False, "error": str(e)})
    return results


def run_zonewalk_full(
    domain: str,
    issue: str = "standard",
    skip_propagation: bool = False,
    deep: bool = False,
    ports: bool = False,
    reputation: bool = False,
) -> ZonewalkResult:
    """Run a full zonewalk diagnosis on a domain. Pure Python, cross-platform."""
    result = ZonewalkResult(domain=domain, timestamp=datetime.now(timezone.utc).isoformat())
    res = Resolver()

    # ── Nameservers & Provider ──
    ns_records = res.ns(domain)
    result.nameservers = ns_records

    provider = "Unknown / External"
    hosting_type = ""
    is_grid = False

    for ns in ns_records:
        ns_lower = ns.lower()
        for pattern, htype in GRID_NS_PATTERNS.items():
            if pattern in ns_lower:
                is_grid = True
                provider = "1-grid"
                hosting_type = htype
                break
        if is_grid:
            break

    if not is_grid:
        for pattern, name in COMPETITORS:
            if any(pattern in ns.lower() for ns in ns_records):
                provider = name
                break

    result.hosting_provider = provider
    result.hosting_type = hosting_type
    result.is_grid = is_grid
    if not is_grid and not any("cloudflare" in ns.lower() for ns in ns_records):
        result.issues.append(f"NOT_GRID: External provider - {provider}")

    if not ns_records:
        result.issues.append("NO_NS: No nameserver records found")

    # ── WHOIS ──
    result.whois = whois_lookup(domain)

    # ── A / AAAA ──
    result.a_records = res.a(domain)
    result.aaaa_records = res.aaaa(domain)
    if not result.a_records:
        result.issues.append("NO_A_RECORD: No A record found")

    # ── PTR ──
    if result.a_records:
        ptr = res.ptr(result.a_records[0])
        result.ptr_record = ptr
        if not ptr:
            result.issues.append("NO_PTR: No PTR record")
        elif domain not in ptr:
            result.issues.append(f"PTR_MISMATCH: PTR ({ptr}) does not match domain")

    # ── MX ──
    result.mx_records = res.mx(domain)

    # ── SPF / DKIM / DMARC ──
    txt_records = res.txt(domain)
    result.txt_records = txt_records
    spf = [t for t in txt_records if t.startswith("v=spf1")]
    if spf:
        result.spf_record = spf[0]
        result.has_mailchannels = "mailchannels" in spf[0].lower()
        lookup_count = spf[0].count("include:")
        if lookup_count > 8:
            result.issues.append("SPF_TOO_MANY_LOOKUPS: SPF lookups exceed 10 limit")
    else:
        result.issues.append("NO_SPF: Missing SPF record")

    for selector in DKIM_SELECTORS:
        dkim = res.txt(f"{selector}._domainkey.{domain}")
        for d in dkim:
            result.dkim_records.append(f"{selector}: {d}")
        if dkim:
            break
    if not result.dkim_records:
        result.issues.append("NO_DKIM: No DKIM record found")

    dmarc_records = res.txt(f"_dmarc.{domain}")
    if dmarc_records:
        dmarc = dmarc_records[0]
        result.dmarc_record = dmarc
        policy = re.search(r"p=(\w+)", dmarc)
        if policy and policy.group(1) == "none":
            result.issues.append("DMARC_NONE: DMARC policy is 'none'")
    else:
        result.issues.append("NO_DMARC: Missing DMARC record")

    # ── SOA ──
    result.soa = res.soa(domain)

    # ── HTTP / HTTPS / SSL ──
    http_s, https_s, ssl_d = http_check(domain)
    result.http_status = http_s
    result.https_status = https_s
    result.ssl_expiry_days = ssl_d
    if ssl_d is not None and ssl_d < 0:
        result.issues.append("SSL_EXPIRED")
    elif ssl_d is not None and ssl_d < 14:
        result.issues.append("SSL_EXPIRY_CRITICAL")
    if http_s and http_s.get("status_code") == 0:
        result.issues.append("HTTP_NO_RESPONSE")
    elif http_s and http_s.get("status_code", 0) >= 500:
        result.issues.append("HTTP_5XX")
    elif http_s and http_s.get("status_code", 0) == 404:
        result.issues.append("HTTP_404")

    # ── Propagation ──
    if not skip_propagation and result.a_records:
        result.propagation = check_propagation(domain, result.a_records)

    # ── Ports ──
    if ports:
        open_ports = port_scan(domain)
        result.open_ports = open_ports

    # ── Reputation ──
    if reputation and result.a_records:
        result.blocklists = check_blocklists(result.a_records[0])

    # ── Subdomains ──
    if deep:
        result.subdomains = enum_subdomains(domain)

    result.success = True
    return result


def run_zonewalk(domain: str, flags: list[str] = None) -> dict:
    """Run zonewalk and return dict (compatible with old interface)."""
    if flags is None:
        flags = []
    issue = "standard"
    skip_prop = False
    deep = False
    ports = False
    reputation = False
    ptr_only = False

    for f in flags:
        if f.startswith("--issue"):
            idx = flags.index(f)
            if idx + 1 < len(flags):
                issue = flags[idx + 1]
        if f == "--deep":
            deep = True
        if f == "--ports":
            ports = True
        if f == "--ip-reputation":
            reputation = True
        if f == "--skip-propagation":
            skip_prop = True
        if f == "--ptr":
            ptr_only = True

    try:
        result = run_zonewalk_full(
            domain,
            issue=issue,
            skip_propagation=skip_prop,
            deep=deep,
            ports=ports,
            reputation=reputation,
        )
        if ptr_only:
            # Return just PTR consistency info
            return {
                "domain": domain,
                "success": result.success,
                "stdout": json.dumps({
                    "ptr": result.ptr_record,
                    "a_records": result.a_records,
                    "issues": result.issues,
                }, indent=2),
                "stderr": "",
                "error": "",
                "note": "",
            }
        return {
            "domain": domain,
            "success": result.success,
            "stdout": format_zonewalk_output(result),
            "stderr": "",
            "error": "",
            "note": f"Zonewalk v3.1 (Python) - {result.hosting_provider}",
        }
    except Exception as e:
        return {
            "domain": domain,
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "error": f"zonewalk failed: {e}",
            "note": "",
        }


def format_zonewalk_output(result: ZonewalkResult) -> str:
    """Format zonewalk result as human-readable text (like zonewalk.sh)."""
    lines = []
    lines.append(f"ZONEWALK v3.1 (Python) - {result.domain}")
    lines.append(f"  Started: {result.timestamp}")
    lines.append("")

    # Nameservers
    lines.append(">> Nameserver & Hosting Detection")
    if result.nameservers:
        for ns in result.nameservers:
            lines.append(f"    {ns}")
        if result.is_grid:
            lines.append(f"  OK Hosted with 1-grid ({result.hosting_type})")
        else:
            lines.append(f"  External provider: {result.hosting_provider}")
    else:
        lines.append("  FAIL No NS records found")
    lines.append("")

    # WHOIS
    if result.whois.get("registrar"):
        lines.append(f"  Registrar: {result.whois['registrar']}")
    if result.whois.get("expiry"):
        lines.append(f"  Expires:   {result.whois['expiry']}")
    lines.append("")

    # A record
    lines.append(">> A Record & IP Info")
    if result.a_records:
        lines.append(f"  OK A record: {', '.join(result.a_records)}")
    else:
        lines.append("  FAIL No A record found")
    lines.append("")

    # PTR
    lines.append(">> Reverse DNS (PTR)")
    if result.a_records:
        ip = result.a_records[0]
        if result.ptr_record:
            lines.append(f"  OK PTR: {result.ptr_record}")
            if result.domain not in result.ptr_record:
                lines.append(f"  WARN PTR does not match domain")
        else:
            lines.append(f"  FAIL No PTR record for {ip}")
    lines.append("")

    # MX
    lines.append(">> MX Records (Mail Routing)")
    if result.mx_records:
        for pref, host in result.mx_records:
            lines.append(f"    {pref} {host}")
    else:
        lines.append("  FAIL No MX records found")
    lines.append("")

    # Mail auth
    lines.append(">> Mail Authentication (SPF / DKIM / DMARC)")
    lines.append(f"  SPF: {'OK' if result.spf_record else 'MISSING'}")
    if result.spf_record:
        lines.append(f"    {result.spf_record[:120]}")
        if result.has_mailchannels:
            lines.append(f"    OK MailChannels authorised")
        else:
            lines.append(f"    FAIL MailChannels NOT in SPF")
    lines.append(f"  DKIM: {'OK' if result.dkim_records else 'MISSING'}")
    if result.dkim_records:
        lines.append(f"    {result.dkim_records[0][:100]}")
    lines.append(f"  DMARC: {'OK' if result.dmarc_record else 'MISSING'}")
    if result.dmarc_record:
        lines.append(f"    {result.dmarc_record[:100]}")
        if "p=none" in result.dmarc_record:
            lines.append(f"    WARN Policy is 'none'")
    lines.append("")

    # SOA
    if result.soa:
        lines.append(">> SOA Record (Zone Health)")
        lines.append(f"  Serial: {result.soa['serial']}")
        soa = result.soa
        lines.append(f"  MNAME: {soa['mname']}  Refresh: {soa['refresh']}s  Retry: {soa['retry']}s")
        lines.append("")

    # HTTP
    lines.append(">> Web / HTTP Check")
    if result.http_status:
        code = result.http_status.get("status_code", "No response")
        lines.append(f"  HTTP: {code}")
    if result.https_status:
        code = result.https_status.get("status_code", "No response")
        lines.append(f"  HTTPS: {code}")
    if result.ssl_expiry_days is not None:
        lines.append(f"  SSL: {result.ssl_expiry_days} days until expiry")
    lines.append("")

    # Ports
    if result.open_ports:
        lines.append(">> Port Scan")
        for p, name in result.open_ports:
            lines.append(f"  Port {p} ({name}): OPEN")
        lines.append("")

    # Blocklists
    if result.blocklists:
        lines.append(">> IP Reputation")
        for bl in result.blocklists:
            status = "LISTED" if bl["listed"] else "Clean"
            lines.append(f"  {bl['list']}: {status}")
        lines.append("")

    # Subdomains
    if result.subdomains:
        lines.append(">> Subdomain Enumeration")
        for sd in result.subdomains[:10]:
            if sd.get("ips"):
                lines.append(f"  {sd['subdomain']} -> {', '.join(sd['ips'])}")
            elif sd.get("cname"):
                lines.append(f"  {sd['subdomain']} -> CNAME {sd['cname']}")
        if len(result.subdomains) > 10:
            lines.append(f"  ... and {len(result.subdomains) - 10} more")
        lines.append("")

    # Propagation
    if result.propagation:
        lines.append(">> DNS Propagation")
        for p in result.propagation:
            match_str = "MATCH" if p["match"] else "MISMATCH"
            result_str = ", ".join(p["result"]) if p["result"] else "NONE"
            lines.append(f"  {p['resolver']:15s} ({p['ip']:15s}): {result_str:20s} {match_str}")
        lines.append("")

    # Issues
    if result.issues:
        lines.append(f">> Issues Found ({len(result.issues)})")
        for iss in result.issues:
            lines.append(f"  {iss}")
    else:
        lines.append(">> All checks passed - no issues found")
    lines.append("")

    return "\n".join(lines)


def run_dig(domain: str, query_type: str = "ANY") -> dict:
    """DNS lookup (dig equivalent)."""
    try:
        res = Resolver()
        rdtype = query_type.upper()
        if rdtype == "ANY":
            results = {}
            for t in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
                try:
                    r = res._resolve(domain, t)
                    if r:
                        results[t] = r
                except Exception:
                    pass
            return {"success": True, "stdout": json.dumps(results, indent=2), "domain": domain}
        else:
            r = res._resolve(domain, rdtype)
            return {"success": True, "stdout": json.dumps(r), "domain": domain}
    except Exception as e:
        return {"success": False, "error": str(e)}


def run_whois(domain: str) -> dict:
    """WHOIS lookup."""
    data = whois_lookup(domain)
    return {"success": bool(data.get("registrar")), "stdout": json.dumps(data, indent=2)}


def parse_email_headers(raw_headers: str) -> dict:
    """Parse and analyze email headers (zonewalk --headers equivalent)."""
    analysis = {
        "from": "",
        "to": "",
        "subject": "",
        "date": "",
        "return_path": "",
        "reply_to": "",
        "spf_result": "",
        "dkim_result": "",
        "dmarc_result": "",
        "arc_result": "",
        "spam_score": "",
        "originating_ip": "",
        "hops": [],
        "issues": [],
        "block_reason": "",
    }

    for line in raw_headers.splitlines():
        l = line.lower()
        if l.startswith("from:") and not analysis["from"]:
            analysis["from"] = line.split(":", 1)[1].strip()
        elif l.startswith("to:") and not analysis["to"]:
            analysis["to"] = line.split(":", 1)[1].strip()
        elif l.startswith("subject:") and not analysis["subject"]:
            analysis["subject"] = line.split(":", 1)[1].strip()
        elif l.startswith("date:") and not analysis["date"]:
            analysis["date"] = line.split(":", 1)[1].strip()
        elif l.startswith("return-path:") and not analysis["return_path"]:
            analysis["return_path"] = line.split(":", 1)[1].strip().strip("<>")
        elif l.startswith("reply-to:") and not analysis["reply_to"]:
            analysis["reply_to"] = line.split(":", 1)[1].strip()
        elif "authentication-results" in l:
            for tag in ["spf", "dkim", "dmarc", "arc"]:
                m = re.search(rf"{tag}=(\S+)", l)
                if m:
                    analysis[f"{tag}_result"] = m.group(1)
        elif l.startswith("x-spam-score:"):
            analysis["spam_score"] = line.split(":", 1)[1].strip()
        elif l.startswith("x-spam-status:"):
            analysis["spam_status"] = line.split(":", 1)[1].strip()

    # Extract originating IP from bottom-most Received header
    received = [l for l in raw_headers.splitlines() if l.lower().startswith("received:")]
    if received:
        last_rec = received[-1]
        ips = re.findall(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?", last_rec)
        if ips:
            analysis["originating_ip"] = ips[0]
        analysis["hops"] = [r.strip() for r in received]

    # Detect block reasons
    if "550-5.7.1" in raw_headers:
        analysis["block_reason"] = "Gmail 550-5.7.1: SPF/DKIM/DMARC authentication failure"
    elif "550-5.7.26" in raw_headers:
        analysis["block_reason"] = "Gmail 550-5.7.26: ARC authentication failed (forwarded mail)"
    elif "spf=hardfail" in raw_headers or "spf=fail" in raw_headers:
        analysis["block_reason"] = "SPF hardfail: sender IP not authorised"
    elif "dkim=fail" in raw_headers:
        analysis["block_reason"] = "DKIM fail: signature invalid"
    elif "dmarc=fail" in raw_headers:
        analysis["block_reason"] = "DMARC fail: neither SPF nor DKIM passed alignment"

    return analysis


# ── Issue-specific diagnostics ──
def diagnose_mail_send(domain: str) -> str:
    """Diagnose outbound mail issues."""
    r = run_zonewalk_full(domain, issue="mail-send")
    lines = [f"Outbound Mail Diagnosis for {domain}"]
    lines.append(f"  SPF: {'OK' if r.spf_record else 'MISSING'}")
    lines.append(f"  DKIM: {'OK' if r.dkim_records else 'MISSING'}")
    lines.append(f"  DMARC: {'OK' if r.dmarc_record else 'MISSING'}")
    lines.append(f"  PTR: {r.ptr_record or 'MISSING'}")
    lines.append(f"  MailChannels: {'OK' if r.has_mailchannels else 'NOT IN SPF'}")
    if not r.ptr_record:
        lines.append("  WARN Missing PTR - affects Gmail delivery")
    return "\n".join(lines)


def diagnose_mail_recv(domain: str) -> str:
    """Diagnose inbound mail issues."""
    r = run_zonewalk_full(domain, issue="mail-recv", ports=True)
    lines = [f"Inbound Mail Diagnosis for {domain}"]
    if r.mx_records:
        lines.append("  MX Records:")
        for pref, host in r.mx_records:
            lines.append(f"    {pref} {host}")
    else:
        lines.append("  FAIL No MX records")
    smtp_ports = [p for p, n in r.open_ports if n in ("SMTP", "SMTPS", "SMTP-Submission")]
    if smtp_ports:
        lines.append(f"  SMTP ports open: {[p for p,n in r.open_ports if 'SMTP' in n]}")
    else:
        lines.append("  WARN No common SMTP ports open")
    return "\n".join(lines)
