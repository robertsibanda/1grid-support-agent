import json
import os
import re
import logging
from datetime import datetime

import pymongo
from bson import ObjectId

logger = logging.getLogger(__name__)


class MongoWarehouse:
    """MongoDB document warehouse for the 1grid support system."""

    URI = "mongodb://localhost:27017"
    DB_NAME = "1grid"

    def __init__(self):
        self.client = pymongo.MongoClient(self.URI)
        self.db = self.client[self.DB_NAME]

        # collections
        self.tickets = self.db["tickets"]
        self.issues = self.db["issues"]
        self.servers = self.db["servers"]
        self.conversations = self.db["conversations"]
        self.quickrefs = self.db["quickrefs"]
        self.clients = self.db["clients"]
        self.canned = self.db["canned"]
        self.sops = self.db["sops"]
        self.patterns = self.db["patterns"]

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
            collection.delete_many({})
            docs = []
            for r in rows:
                doc = dict(r)
                for k, v in doc.items():
                    if isinstance(v, datetime):
                        doc[k] = v.isoformat()
                docs.append(doc)
            if docs:
                collection.insert_many(docs, ordered=False)
            counts[sqlite_table] = len(docs)

        conn.close()

        for col_name, col in mapping.items():
            col.create_index("domain")
            col.create_index("ticket_ref")
            col.create_index("server_ip")
            col.create_index("created_at")

        return counts

    def import_conversations(self, jsonl_path: str) -> int:
        self.conversations.delete_many({})
        if not os.path.exists(jsonl_path):
            return 0
        count = 0
        docs = []
        with open(jsonl_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        docs.append(json.loads(line))
                        count += 1
                    except Exception:
                        pass
        if docs:
            self.conversations.insert_many(docs, ordered=False)
            self.conversations.create_index("id")
            self.conversations.create_index("timestamp")
        return count

    # ------------------------------------------------------------------
    # TICKETS
    # ------------------------------------------------------------------
    def search_tickets(self, q: str = "", limit: int = 20):
        if not q:
            cursor = self.tickets.find().sort("created_at", pymongo.DESCENDING).limit(limit)
        else:
            import re
            pat = re.compile(re.escape(q), re.IGNORECASE)
            cursor = (self.tickets.find(
                {"$or": [
                    {"domain": pat},
                    {"ticket_ref": pat},
                    {"description": pat},
                    {"server_ip": pat},
                    {"ptr": pat},
                ]}
            ).sort("created_at", pymongo.DESCENDING).limit(limit))
        return [self._serialize(d) for d in cursor]

    def tickets_by_server(self):
        pipeline = [
            {"$match": {"server_ip": {"$ne": ""}}},
            {"$group": {
                "_id": "$server_ip",
                "ptr": {"$first": "$ptr"},
                "count": {"$sum": 1},
                "domains": {"$addToSet": "$domain"},
                "categories": {"$addToSet": "$category"},
                "sub_categories": {"$addToSet": "$sub_category"},
                "outcomes": {"$addToSet": "$outcome"},
            }},
            {"$sort": {"count": -1}},
        ]
        results = []
        for d in self.tickets.aggregate(pipeline):
            results.append({
                "server_ip": d["_id"],
                "ptr": d.get("ptr", ""),
                "count": d["count"],
                "domains": ", ".join(sorted(x for x in d.get("domains", []) if x)),
                "categories": ", ".join(sorted(x for x in d.get("categories", []) if x)),
                "sub_categories": ", ".join(sorted(x for x in d.get("sub_categories", []) if x)),
                "outcomes": ", ".join(sorted(x for x in d.get("outcomes", []) if x)),
            })
        return results

    def servers_enriched(self):
        known = {}
        for s in self.servers.find():
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
        if not q:
            cursor = self.issues.find().sort("created_at", pymongo.DESCENDING).limit(limit)
        else:
            import re
            pat = re.compile(re.escape(q), re.IGNORECASE)
            cursor = (self.issues.find(
                {"$or": [
                    {"domain": pat},
                    {"issue_summary": pat},
                    {"resolution": pat},
                    {"ticket_ref": pat},
                ]}
            ).sort("created_at", pymongo.DESCENDING).limit(limit))
        return [self._serialize(d) for d in cursor]

    # ------------------------------------------------------------------
    # QUICK REF
    # ------------------------------------------------------------------
    def get_quick_ref(self, category: str = None):
        if not category:
            return [self._serialize(d) for d in self.quickrefs.find()]
        return [self._serialize(d) for d in self.quickrefs.find({"category": category})]

    def quickref_by_category(self):
        groups = {}
        for r in self.quickrefs.find():
            cat = r.get("category", "General")
            groups.setdefault(cat, []).append(self._serialize(r))
        return groups

    # ------------------------------------------------------------------
    # CANNED / SOP / PATTERNS
    # ------------------------------------------------------------------
    def get_canned_response(self, title: str):
        return [self._serialize(d) for d in self.canned.find({"title": title})]

    def get_sop(self, title: str = None):
        if not title:
            return [self._serialize(d) for d in self.sops.find()]
        return [self._serialize(d) for d in self.sops.find({"title": title})]

    def get_issue_patterns(self, name: str = None):
        if not name:
            return [self._serialize(d) for d in self.patterns.find()]
        return [self._serialize(d) for d in self.patterns.find({"name": name})]

    # ------------------------------------------------------------------
    # SERVERS
    # ------------------------------------------------------------------
    def get_server(self, hostname: str = None, ip: str = None):
        if hostname:
            q = {"hostname": {"$regex": re.escape(hostname), "$options": "i"}}
        elif ip:
            q = {"ip": {"$regex": re.escape(ip), "$options": "i"}}
        else:
            q = {}
        return [self._serialize(d) for d in self.servers.find(q)]

    def search_client(self, query: str):
        import re
        pat = re.compile(re.escape(query), re.IGNORECASE)
        return [self._serialize(d) for d in self.clients.find(
            {"$or": [{"name": pat}, {"email": pat}, {"domains_managed": pat}]}
        )]

    # ------------------------------------------------------------------
    # CONVERSATIONS
    # ------------------------------------------------------------------
    def get_conversations(self, limit: int = 50):
        cursor = self.conversations.find().sort("timestamp", pymongo.DESCENDING).limit(limit)
        return [self._serialize(d) for d in cursor]

    # ------------------------------------------------------------------
    # GENERIC SEARCH
    # ------------------------------------------------------------------
    def search_all(self, query: str):
        import re
        pat = re.compile(re.escape(query), re.IGNORECASE)
        results = {
            "tickets": [self._serialize(d) for d in self.tickets.find({"$or": [
                {"domain": pat}, {"ticket_ref": pat}, {"description": pat}
            ]})],
            "issues": [self._serialize(d) for d in self.issues.find({"$or": [
                {"domain": pat}, {"issue_summary": pat}, {"ticket_ref": pat}
            ]})],
            "kb": [],
        }
        return results

    # ------------------------------------------------------------------
    # COUNTS
    # ------------------------------------------------------------------
    def counts(self):
        return {
            "tickets": self.tickets.count_documents({}),
            "issues": self.issues.count_documents({}),
            "servers": self.servers.count_documents({}),
            "conversations": self.conversations.count_documents({}),
            "quickrefs": self.quickrefs.count_documents({}),
            "clients": self.clients.count_documents({}),
            "canned": self.canned.count_documents({}),
            "sops": self.sops.count_documents({}),
            "patterns": self.patterns.count_documents({}),
        }

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------
    @staticmethod
    def _serialize(doc):
        """Convert ObjectId to string for JSON serialization."""
        if doc is None:
            return None
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        return doc
