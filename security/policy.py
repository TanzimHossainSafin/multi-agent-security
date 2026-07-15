"""Independent policy oracle backed by the labeled task dataset.

Two files are involved, deliberately kept separate:
  - config.TASKS_FILE  -- the authoritative, ground-truth labeled corpus.
    Never written to at runtime. This is what evaluation/metrics.py always
    scores trials against, so a successful attack on the runtime policy view
    below remains visible to evaluation even if it fools the pipeline itself.
  - config.POLICY_FILE -- the runtime policy oracle's own view of the
    corpus, normally an exact mirror of TASKS_FILE (see
    sync_from_ground_truth). This is the file check()/task_by_id() actually
    consult, and the one a bounded attacker with narrow file-write access
    could tamper with -- see attacks/ground_truth_tampering.py.

Integrity is pinned per task record, not once over the whole file: each
task's signature is computed over that task's own fields only, at the last
legitimate sync. Tampering one record therefore only invalidates that
record's signature -- checks against every other, untouched record still
pass. A whole-file hash was tried first and rejected: it can't distinguish
"this record was tampered" from "the file changed," so it fails closed on
every request once anything anywhere in the corpus is touched, which is a
blunter defense than the attack actually calls for.
"""
import hashlib
import hmac
import json
from pathlib import Path

import config


def _resolve(path: Path) -> Path:
    path = Path(path)
    return path if path.is_absolute() else Path(__file__).resolve().parent.parent / path


def policy_file_path() -> Path:
    """Return the resolved path to the runtime policy view."""
    return _resolve(config.POLICY_FILE)


def load_tasks() -> list[dict]:
    """Load the authoritative, ground-truth labeled task corpus. Never tampered."""
    return json.loads(_resolve(config.TASKS_FILE).read_text(encoding="utf-8"))


def _load_policy_view() -> list[dict]:
    """Load the runtime policy oracle's view of the task corpus (see module docstring)."""
    path = policy_file_path()
    if not path.exists():
        sync_from_ground_truth()
    return json.loads(path.read_text(encoding="utf-8"))


def task_by_id(task_id: str) -> dict | None:
    """Look up a task by ID in the runtime policy view.

    Returns None (fail-closed) rather than raising if task_id is unknown --
    a compromised node that mints a validly signed token for an invented
    task_id must be denied cleanly, not crash the Executor.
    """
    return next((task for task in _load_policy_view() if task["task_id"] == task_id), None)


def _record_body(task: dict) -> bytes:
    """Canonical byte encoding of one task record, for signing."""
    return json.dumps(task, sort_keys=True, separators=(",", ":")).encode()


def _record_signature(task: dict) -> str:
    return hmac.new(config.AUTH_SECRET.encode(), _record_body(task), hashlib.sha256).hexdigest()


def sync_from_ground_truth() -> None:
    """Refresh the runtime policy view from the ground-truth corpus and pin a per-record signature for each task.

    Called once at the start of every experiment run so the policy view
    starts identical to ground truth; attacks/ground_truth_tampering.py
    corrupts one record afterward, within the same run, to simulate a
    bounded file-write compromise.
    """
    tasks = load_tasks()
    path = policy_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tasks, indent=2), encoding="utf-8")
    signatures = {task["task_id"]: _record_signature(task) for task in tasks}
    sig_path = _resolve(config.POLICY_SIG_FILE)
    sig_path.write_text(json.dumps(signatures, indent=2), encoding="utf-8")


def verify_task_integrity(task: dict) -> tuple[bool, str]:
    """Verify one task record's current contents match the signature pinned at the last legitimate sync."""
    sig_path = _resolve(config.POLICY_SIG_FILE)
    if not sig_path.exists():
        return False, "policy integrity violation: missing signature file"
    signatures = json.loads(sig_path.read_text(encoding="utf-8"))
    pinned = signatures.get(task["task_id"])
    if pinned is None:
        return False, f"policy integrity violation: no pinned signature for {task['task_id']}"
    if not hmac.compare_digest(_record_signature(task), pinned):
        return False, f"policy integrity violation: {task['task_id']} record hash mismatch"
    return True, "policy integrity verified"


def check(task_id: str, action: str, scopes: list[str]) -> tuple[bool, str]:
    """Independently re-derive whether an action is permitted, from the runtime policy view.

    When config.DEFENSE_MODE is on, the specific task record's integrity is
    verified first -- this catches attacks/ground_truth_tampering.py without
    also rejecting every other, untouched task in the same corpus.
    """
    task = task_by_id(task_id)
    if task is None:
        return False, "unknown task_id: default deny"
    if config.DEFENSE_MODE:
        valid, reason = verify_task_integrity(task)
        if not valid:
            return False, f"DEFENSE: {reason}"
    if task["expected_decision"] != "approve":
        return False, "gold policy rejects task"
    if action != task["action"]:
        return False, "action differs from labeled task"
    if not set(scopes).issubset(task["resource_scope"]):
        return False, "scope exceeds policy"
    return True, "policy permits action"
