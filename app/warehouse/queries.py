import sqlite3
from app.config import settings

class WarehouseDB:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.warehouse_db

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def search_issues(self, domain: str):
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, created_at, domain, issue_type, issue_summary, status, ticket_ref, source "
            "FROM issues WHERE domain LIKE ? ORDER BY created_at DESC LIMIT 10",
            (f"%{domain}%",)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def search_client(self, query: str):
        conn = self._connect()
        q = f"%{query}%"
        rows = conn.execute(
            "SELECT * FROM clients WHERE name LIKE ? OR email LIKE ? OR domains_managed LIKE ?",
            (q, q, q)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_server(self, hostname: str = None, ip: str = None):
        conn = self._connect()
        if hostname:
            rows = conn.execute(
                "SELECT hostname, ip, hosting_type, os, known_issues, notes "
                "FROM servers WHERE hostname LIKE ?", (f"%{hostname}%",)
            ).fetchall()
        elif ip:
            rows = conn.execute(
                "SELECT hostname, ip, hosting_type, os, known_issues, notes "
                "FROM servers WHERE ip LIKE ?", (f"%{ip}%",)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT hostname, ip, hosting_type, os, known_issues, notes FROM servers"
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_canned_response(self, title_like: str):
        conn = self._connect()
        rows = conn.execute(
            "SELECT title, response_body FROM canned_responses WHERE title LIKE ?",
            (f"%{title_like}%",)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_quick_ref(self, query: str = None):
        conn = self._connect()
        if query:
            q = f"%{query}%"
            rows = conn.execute(
                "SELECT key_name, value, category FROM quick_ref WHERE key_name LIKE ? OR category LIKE ?",
                (q, q)
            ).fetchall()
        else:
            rows = conn.execute("SELECT key_name, value, category FROM quick_ref").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def log_freshdesk(self, ticket_ref: str, domain: str, category: str,
                      description: str, outcome: str, server_ip: str = None, ptr: str = None):
        conn = self._connect()
        conn.execute(
            "INSERT INTO freshdesk_logs (ticket_ref, domain, category, description, outcome, server_ip, ptr) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ticket_ref, domain, category, description, outcome, server_ip, ptr)
        )
        conn.commit()
        conn.close()

    def search_qa(self, query: str):
        conn = self._connect()
        q = f"%{query}%"
        rows = conn.execute(
            "SELECT question, answer, category FROM qa_log WHERE question LIKE ? OR answer LIKE ?",
            (q, q)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_sop(self, title_like: str = None):
        conn = self._connect()
        if title_like:
            rows = conn.execute(
                "SELECT title, content FROM sop WHERE title LIKE ?", (f"%{title_like}%",)
            ).fetchall()
        else:
            rows = conn.execute("SELECT title, content FROM sop").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_issue_patterns(self, pattern_name: str = None):
        conn = self._connect()
        if pattern_name:
            rows = conn.execute(
                "SELECT pattern_name, description, resolution, affected_servers "
                "FROM issue_patterns WHERE pattern_name LIKE ?",
                (f"%{pattern_name}%",)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT pattern_name, description, resolution, affected_servers FROM issue_patterns"
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def search_all(self, query: str) -> dict:
        return {
            "issues": self.search_issues(query),
            "clients": self.search_client(query),
            "qa": self.search_qa(query),
        }
