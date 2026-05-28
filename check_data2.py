import sqlite3
c = sqlite3.connect("data/support_warehouse.db")
c.row_factory = sqlite3.Row

print("=== freshdesk_logs (first 3) ===")
for r in c.execute("SELECT * FROM freshdesk_logs LIMIT 3").fetchall():
    print(dict(r))
print()

print("=== quick_ref (first 3) ===")
for r in c.execute("SELECT * FROM quick_ref LIMIT 3").fetchall():
    print(dict(r))
print()

print("=== issue_patterns ===")
for r in c.execute("SELECT * FROM issue_patterns").fetchall():
    print(dict(r))
print()

print("=== issues (first 3) ===")
for r in c.execute("SELECT * FROM issues LIMIT 3").fetchall():
    print(dict(r))
print()

print("=== servers ===")
for r in c.execute("SELECT * FROM servers").fetchall():
    print(dict(r))
print()

print("=== quick_ref categories ===")
for r in c.execute("SELECT DISTINCT category FROM quick_ref").fetchall():
    print(dict(r))
