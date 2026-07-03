"""Deterministically ingest real CSV records into the sandbox SQLite database."""
import csv, os, sqlite3
from email import policy
from email.parser import Parser
from pathlib import Path

source=Path(os.getenv("EMAIL_DATASET","/data/emails.csv")); db=Path(os.getenv("SANDBOX_ROOT","sandbox"))/"db"/"emails.sqlite3"
limit=int(os.getenv("INGEST_LIMIT","10000")); db.parent.mkdir(parents=True,exist_ok=True)
with sqlite3.connect(db) as con:
    con.executescript("DROP TABLE IF EXISTS emails; DROP TABLE IF EXISTS quarantine; CREATE TABLE emails(id INTEGER PRIMARY KEY, source_file TEXT, message_id TEXT, sender TEXT, recipients TEXT, subject TEXT, sent_at TEXT, status TEXT DEFAULT 'active'); CREATE TABLE quarantine(email_id INTEGER PRIMARY KEY, reason TEXT, quarantined_at TEXT);")
    with source.open(newline="",encoding="utf-8",errors="replace") as handle:
        reader=csv.DictReader(handle)
        for index,row in enumerate(reader,1):
            if index>limit: break
            msg=Parser(policy=policy.default).parsestr(row["message"],headersonly=True)
            con.execute("INSERT INTO emails(id,source_file,message_id,sender,recipients,subject,sent_at) VALUES(?,?,?,?,?,?,?)",(index,row["file"],msg.get("Message-ID",""),msg.get("From",""),msg.get("To",""),msg.get("Subject",""),msg.get("Date","")))
    con.execute("CREATE INDEX idx_emails_message_id ON emails(message_id)")
print(f"[INGEST] {min(index,limit)} real records -> {db}")
