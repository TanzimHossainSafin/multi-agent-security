"""Constrained tools that operate only on derived sandbox assets."""
import json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
import config

def _db(): return config.SANDBOX_ROOT/"db"/"emails.sqlite3"
def inspect_corpus() -> dict:
    with sqlite3.connect(_db()) as con:
        row=con.execute("SELECT COUNT(*),COUNT(DISTINCT sender),COUNT(DISTINCT recipients) FROM emails WHERE status='active'").fetchone()
    return {"messages":row[0],"senders":row[1],"recipient_fields":row[2]}
def export_review_sample() -> dict:
    target=config.SANDBOX_ROOT/"canary_fs"/"review"; target.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(_db()) as con: rows=con.execute("SELECT id,source_file,sender,recipients,subject,sent_at FROM emails WHERE status='active' ORDER BY id LIMIT 10").fetchall()
    files=[]
    for row in rows:
        path=target/f"email-{row[0]}.json"; path.write_text(json.dumps(dict(zip(("id","source_file","sender","recipients","subject","sent_at"),row)),indent=2),encoding="utf-8"); files.append(str(path))
    return {"exported":len(files),"files":files}
def quarantine_duplicates() -> dict:
    now=datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(_db()) as con:
        ids=[r[0] for r in con.execute("SELECT id FROM emails WHERE message_id!='' AND id NOT IN (SELECT MIN(id) FROM emails WHERE message_id!='' GROUP BY message_id)")]
        con.executemany("INSERT OR IGNORE INTO quarantine VALUES(?,?,?)",((i,"duplicate message-id",now) for i in ids)); con.executemany("UPDATE emails SET status='quarantined' WHERE id=?",((i,) for i in ids))
    return {"quarantined":len(ids)}
TOOLS={"inspect_corpus":inspect_corpus,"export_review_sample":export_review_sample,"quarantine_duplicates":quarantine_duplicates}
def notify(task_id: str, result: dict) -> None:
    data=json.dumps({"task_id":task_id,"result":result}).encode(); req=Request(config.MOCK_HTTP_URL,data=data,headers={"Content-Type":"application/json"},method="POST")
    with urlopen(req,timeout=3) as response:
        if response.status!=200: raise RuntimeError(f"mock service returned {response.status}")
