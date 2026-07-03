"""Independent policy oracle backed by the labeled task dataset."""
import json
from pathlib import Path

TASK_FILE=Path(__file__).resolve().parent.parent/"data"/"tasks.json"
def load_tasks() -> list[dict]: return json.loads(TASK_FILE.read_text(encoding="utf-8"))
def task_by_id(task_id: str) -> dict: return next(x for x in load_tasks() if x["task_id"]==task_id)
def check(task_id: str, action: str, scopes: list[str]) -> tuple[bool,str]:
    task=task_by_id(task_id)
    if task["expected_decision"]!="approve": return False,"gold policy rejects task"
    if action!=task["action"]: return False,"action differs from labeled task"
    if not set(scopes).issubset(task["resource_scope"]): return False,"scope exceeds policy"
    return True,"policy permits action"
