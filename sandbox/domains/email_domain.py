"""Email sandbox domain: SQLite-backed inbox with real, deterministic records.

Implements the Domain contract in sandbox/domains/base.py. This is the only
module that knows the email schema; agent and executor code interacts with it
only through TOOLS, evidence(), notify(), and ingest().
"""

import csv
import json
import os
import sqlite3
from datetime import datetime, timezone
from email import policy as email_policy
from email.parser import Parser
from pathlib import Path
from urllib.request import Request, urlopen

import config

name = "email"


def _db() -> Path:
    return config.SANDBOX_ROOT / "db" / "emails.sqlite3"


def inspect_corpus() -> dict:
    """Return message, sender, and recipient-field counts for active records."""
    with sqlite3.connect(_db()) as con:
        row = con.execute(
            "SELECT COUNT(*), COUNT(DISTINCT sender), COUNT(DISTINCT recipients) "
            "FROM emails WHERE status='active'"
        ).fetchone()
    return {"messages": row[0], "senders": row[1], "recipient_fields": row[2]}


def export_review_sample() -> dict:
    """Write ten active email records into the canary review directory."""
    target = config.SANDBOX_ROOT / "canary_fs" / "review"
    target.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(_db()) as con:
        rows = con.execute(
            "SELECT id, source_file, sender, recipients, subject, sent_at "
            "FROM emails WHERE status='active' ORDER BY id LIMIT 10"
        ).fetchall()
    files = []
    for row in rows:
        path = target / f"email-{row[0]}.json"
        path.write_text(
            json.dumps(dict(zip(("id", "source_file", "sender", "recipients", "subject", "sent_at"), row)), indent=2),
            encoding="utf-8",
        )
        files.append(str(path))
    return {"exported": len(files), "files": files}


def quarantine_duplicates() -> dict:
    """Quarantine records that share a duplicate Message-ID."""
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(_db()) as con:
        ids = [
            r[0]
            for r in con.execute(
                "SELECT id FROM emails WHERE message_id!='' AND id NOT IN "
                "(SELECT MIN(id) FROM emails WHERE message_id!='' GROUP BY message_id)"
            )
        ]
        con.executemany(
            "INSERT OR IGNORE INTO quarantine VALUES(?,?,?)",
            ((i, "duplicate message-id", now) for i in ids),
        )
        con.executemany("UPDATE emails SET status='quarantined' WHERE id=?", ((i,) for i in ids))
    return {"quarantined": len(ids)}


TOOLS = {
    "inspect_corpus": inspect_corpus,
    "export_review_sample": export_review_sample,
    "quarantine_duplicates": quarantine_duplicates,
}


def evidence() -> dict:
    """Factual sandbox summary exposed to the Researcher agent."""
    return inspect_corpus()


def notify(task_id: str, result: dict) -> None:
    """Report a completed action to the local mock HTTP service."""
    data = json.dumps({"task_id": task_id, "result": result}).encode()
    req = Request(config.MOCK_HTTP_URL, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=3) as response:
        if response.status != 200:
            raise RuntimeError(f"mock service returned {response.status}")


def ingest() -> None:
    """Deterministically load real CSV records into the sandbox SQLite database."""
    source = Path(os.getenv("EMAIL_DATASET", "/data/emails.csv"))
    limit = int(os.getenv("INGEST_LIMIT", "10000"))
    db = _db()
    db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db) as con:
        con.executescript(
            "DROP TABLE IF EXISTS emails; DROP TABLE IF EXISTS quarantine; "
            "CREATE TABLE emails(id INTEGER PRIMARY KEY, source_file TEXT, message_id TEXT, "
            "sender TEXT, recipients TEXT, subject TEXT, sent_at TEXT, status TEXT DEFAULT 'active'); "
            "CREATE TABLE quarantine(email_id INTEGER PRIMARY KEY, reason TEXT, quarantined_at TEXT);"
        )
        with source.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle)
            index = 0
            for index, row in enumerate(reader, 1):
                if index > limit:
                    break
                msg = Parser(policy=email_policy.default).parsestr(row["message"], headersonly=True)
                con.execute(
                    "INSERT INTO emails(id,source_file,message_id,sender,recipients,subject,sent_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (index, row["file"], msg.get("Message-ID", ""), msg.get("From", ""), msg.get("To", ""), msg.get("Subject", ""), msg.get("Date", "")),
                )
        con.execute("CREATE INDEX idx_emails_message_id ON emails(message_id)")
    print(f"[INGEST] {min(index, limit)} real records -> {db}")