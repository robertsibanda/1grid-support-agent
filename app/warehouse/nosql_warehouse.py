import json
import os
import logging
from datetime import datetime
from typing import Optional

from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage


class UTF8JSONStorage(JSONStorage):
    """JSONStorage that always uses UTF-8 encoding (fixes cp1252 issues on Windows)."""
    def __init__(self, path, create_dirs=False, **kwargs):
        kwargs.setdefault("encoding", "utf-8")
        super().__init__(path, create_dirs=create_dirs, **kwargs)

logger = logging.getLogger(__name__)


class NoSQLWarehouse:
    """TinyDB-based document data warehouse replacing raw SQLite queries."""

    def __init__(self, db_path: str):
        self._path = db_path
        self.db = TinyDB(db_path, storage=UTF8JSONStorage, indent=2, ensure_ascii=False, sort_keys=True)
        self.Q = Query()

        # document collections
        self.tickets = self.db.table("tickets")
        self.issues = self.db.table("issues")
        self.servers = self.db.table("servers")
        self.conversations = self.db.table("conversations")
        self.quickrefs = self.db.table("quickrefs")
        self.clients = self.db.table("clients")
        self.canned = self.db.table("canned")
        self.sops = self.db.table("sops")
        self.patterns = self.db.table("patterns")

    # ------------------------------------------------------------------
    # IMPORT from SQLite
    # ------------------------------------------------------------------
    def import_from_sqlite(self, sqlite_path: str) -> dict:
        import sqlite3

        conn = sqlite3.connect(sqlite_path)
        conn.row_factory = sqlite3.Row

        mapping = {
            "freshdesk_logs": self.tickets,
            "issues": self.issues,
            "servers": self.servers,
            "clients": self.clients,
            "canned_responses": self.canned,
            "quick_ref": self.quickrefs,
            "sop": self.sops,
            "issue_patterns": self.patterns,
        }

        counts = {}
        for sqlite_table, collection in mapping.items():
            try:
                rows = conn.execute(f"SELECT * FROM [{sqlite_table}]").fetchall()
            except Exception:
                rows = conn.execute(f"SELECT * FROM {sqlite_table}").fetchall()
            collection.truncate()
            for r in rows:
                doc = dict(r)
                for k, v in doc.items():
                    if isinstance(v, datetime):
                        doc[k] = v.isoformat()
                collection.insert(doc)
            counts[sqlite_table] = len(rows)

        conn.close()
        return counts

    def import_conversations(self, jsonl_path: str) -> int:
        self.conversations.truncate()
        if not os.path.exists(jsonl_path):
            return 0
        count = 0
        with open(jsonl_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        self.conversations.insert(json.loads(line))
                        count += 1
                    except Exception:
                        pass
        return count

    # ------------------------------------------------------------------
    # TICKETS
    # ------------------------------------------------------------------
    def search_tickets(self, q: str = "", limit: int = 20):
        all_docs = self.tickets.all()[::-1]
        if not q:
            return all_docs[:limit]
        ql = q.lower()
        out = []
        for t in all_docs:
            if (
                ql in str(t.get("domain", "")).lower()
                or ql in str(t.get("ticket_ref", "")).lower()
                or ql in str(t.get("description", "")).lower()
                or ql in str(t.get("server_ip", "")).lower()
                or ql in str(t.get("ptr", "")).lower()
            ):
                out.append(t)
        return out[:limit]

    def tickets_by_server(self):
        groups = {}
        for t in self.tickets.all():
            ip = t.get("server_ip", "")
            if not ip:
                continue
            if ip not in groups:
                groups[ip] = {
                    "server_ip": ip,
                    "ptr": t.get("ptr", ""),
                    "count": 0,
                    "domains": set(),
                    "categories": set(),
                    "sub_categories": set(),
                    "outcomes": set(),
                }
            g = groups[ip]
            g["count"] += 1
            if t.get("domain"):
                g["domains"].add(t["domain"])
            if t.get("category"):
                g["categories"].add(t["category"])
            if t.get("sub_category"):
                g["sub_categories"].add(t["sub_category"])
            if t.get("outcome"):
                g["outcomes"].add(t["outcome"])

        result = []
        for ip, g in sorted(groups.items(), key=lambda x: x[1]["count"], reverse=True):
            g["domains"] = ", ".join(sorted(g["domains"]))
            g["categories"] = ", ".join(sorted(g["categories"]))
            g["sub_categories"] = ", ".join(sorted(g["sub_categories"]))
            g["outcomes"] = ", ".join(sorted(g["outcomes"]))
            result.append(g)
        return result

    def servers_enriched(self):
        known = {}
        for s in self.servers.all():
            ip = s.get("ip", "")
            if ip:
                known[ip] = s

        by_ip = self.tickets_by_server()
        merged = []
        for s in by_ip:
            ip = s["server_ip"]
            if ip in known:
                k = known[ip]
                s["hostname"] = k.get("hostname", "")
                s["hosting_type"] = k.get("hosting_type", s.get("hosting_type", ""))
                s["os"] = k.get("os", "")
                s["known_issues"] = k.get("known_issues", "")
            merged.append(s)
        return merged

    # ------------------------------------------------------------------
    # ISSUES
    # ------------------------------------------------------------------
    def search_issues(self, q: str = "", limit: int = 20):
        all_docs = sorted(
            self.issues.all(),
            key=lambda x: str(x.get("created_at", "")),
            reverse=True,
        )
        if not q:
            return all_docs[:limit]
        ql = q.lower()
        out = []
        for iss in all_docs:
            if (
                ql in str(iss.get("domain", "")).lower()
                or ql in str(iss.get("issue_summary", "")).lower()
                or ql in str(iss.get("resolution", "")).lower()
                or ql in str(iss.get("ticket_ref", "")).lower()
            ):
                out.append(iss)
        return out[:limit]

    # ------------------------------------------------------------------
    # QUICK REF
    # ------------------------------------------------------------------
    def get_quick_ref(self, category: str = None):
        if not category:
            return self.quickrefs.all()
        return self.quickrefs.search(self.Q.category == category)

    def quickref_by_category(self):
        groups = {}
        for r in self.quickrefs.all():
            cat = r.get("category", "General")
            groups.setdefault(cat, []).append(r)
        return groups

    # ------------------------------------------------------------------
    # CANNED / SOP / PATTERNS
    # ------------------------------------------------------------------
    def get_canned_response(self, title: str):
        return self.canned.search(self.Q.title == title)

    def get_sop(self, title: str = None):
        if not title:
            return self.sops.all()
        return self.sops.search(self.Q.title == title)

    def get_issue_patterns(self, name: str = None):
        if not name:
            return self.patterns.all()
        return self.patterns.search(self.Q.name == name)

    # ------------------------------------------------------------------
    # SERVERS
    # ------------------------------------------------------------------
    def get_server(self, hostname: str = None, ip: str = None):
        if hostname:
            return self.servers.search(self.Q.hostname == hostname)
        if ip:
            return self.servers.search(self.Q.ip == ip)
        return self.servers.all()

    def search_client(self, query: str):
        ql = query.lower()
        return [c for c in self.clients.all() if ql in str(c).lower()]

    # ------------------------------------------------------------------
    # CONVERSATIONS
    # ------------------------------------------------------------------
    def get_conversations(self, limit: int = 50):
        convs = self.conversations.all()
        return convs[-limit:]

    # ------------------------------------------------------------------
    # GENERIC SEARCH
    # ------------------------------------------------------------------
    def search_all(self, query: str):
        ql = query.lower()
        results = {"tickets": [], "issues": [], "kb": []}
        for t in self.tickets.all():
            if ql in str(t).lower():
                results["tickets"].append(t)
        for i in self.issues.all():
            if ql in str(i).lower():
                results["issues"].append(i)
        return results

    # ------------------------------------------------------------------
    # COUNT
    # ------------------------------------------------------------------
    def counts(self):
        return {
            "tickets": len(self.tickets.all()),
            "issues": len(self.issues.all()),
            "servers": len(self.servers.all()),
            "conversations": len(self.conversations.all()),
            "quickrefs": len(self.quickrefs.all()),
            "clients": len(self.clients.all()),
            "canned": len(self.canned.all()),
            "sops": len(self.sops.all()),
            "patterns": len(self.patterns.all()),
        }
