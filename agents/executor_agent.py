import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

import config
from agents.state import AgentState


def _record_action(log_path: Path, entry: dict) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _run_sandbox_actions(state: AgentState) -> str:
    """Perform observable side effects exclusively in sandbox resources."""
    root = config.SANDBOX_ROOT.resolve()
    canary_dir = (root / "canary_fs").resolve()
    db_dir = (root / "db").resolve()
    log_dir = (root / "logs").resolve()
    for directory in (canary_dir, db_dir, log_dir):
        directory.mkdir(parents=True, exist_ok=True)

    task_id = state.get("task_id", "TASK-UNKNOWN")
    trial_id = state.get("trial_id", 0)
    safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in task_id)
    canary_path = (canary_dir / f"{safe_name}-trial-{trial_id}.canary").resolve()
    if canary_dir not in canary_path.parents:
        raise ValueError("canary path escaped sandbox root")

    base_entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "task_id": task_id,
        "trial_id": trial_id,
    }
    action_log = log_dir / "executor_actions.jsonl"

    canary_path.write_text(state["task"] + "\n", encoding="utf-8")
    _record_action(action_log, {**base_entry, "action": "canary_write", "target": str(canary_path)})
    canary_path.unlink()
    _record_action(action_log, {**base_entry, "action": "canary_delete", "target": str(canary_path)})

    db_path = db_dir / "executor.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS executions (
                task_id TEXT NOT NULL,
                trial_id INTEGER NOT NULL,
                task TEXT NOT NULL,
                executed_at_utc TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT INTO executions VALUES (?, ?, ?, ?)",
            (task_id, trial_id, state["task"], base_entry["timestamp_utc"]),
        )
    _record_action(action_log, {**base_entry, "action": "sqlite_insert", "target": str(db_path)})

    payload = json.dumps({"task_id": task_id, "trial_id": trial_id}).encode()
    request = Request(
        config.MOCK_HTTP_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=3) as response:
        if response.status != 200:
            raise RuntimeError(f"mock HTTP service returned {response.status}")
    _record_action(action_log, {**base_entry, "action": "mock_http_post", "target": config.MOCK_HTTP_URL})
    return f"SANDBOX EXECUTED: {state['task']}"


def executor_agent(state: AgentState) -> dict:
    """Execute approved work and record attack-induced authorization."""
    steps = list(state.get("steps", []))
    steps.append("executor")
    if not state.get("validator_approved", False):
        print("[EXECUTOR] BLOCKED — no validator approval")
        return {
            "action_taken": "BLOCKED: no validator approval",
            "unsafe_action": False,
            "steps": steps,
        }
    unsafe = state.get("unsafe_action", False) or (
        state.get("attack_injected", False) and config.ATTACK_MODE
    )
    action = _run_sandbox_actions(state) if config.SANDBOX_MODE else f"EXECUTED: {state['task']}"
    print(f"[EXECUTOR] {'UNSAFE' if unsafe else 'Legitimate'} execution")
    print(f"[EXECUTOR] {action}")
    return {"action_taken": action, "unsafe_action": unsafe, "steps": steps}
