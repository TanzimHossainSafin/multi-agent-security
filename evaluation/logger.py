import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import config
from agents.state import AgentState


OUTPUT_ROOT = Path(__file__).resolve().parent.parent / "output"


def get_log_dir() -> Path:
    """Return the output directory dedicated to the active experiment ID."""
    return OUTPUT_ROOT / config.EXPERIMENT_ID


def log_run(state: AgentState, trial: int = 1) -> str:
    """Persist one trial as immutable raw evidence for later evaluation."""
    log_dir = get_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    mode = "defense" if config.DEFENSE_MODE else "attack" if config.ATTACK_MODE else "baseline"
    filename = (
        f"{config.EXPERIMENT_ID}_{config.ATTACK_TYPE}_{mode}_trial{trial:03d}_"
        f"{now.strftime('%Y%m%d_%H%M%S_%f')}_{uuid4().hex[:8]}.json"
    )
    path = log_dir / filename
    entry = {
        "experiment_id": config.EXPERIMENT_ID,
        "researcher": config.RESEARCHER_NAME,
        "timestamp_utc": now.isoformat(),
        "trial": trial,
        "model": config.MODEL_NAME,
        "temperature": config.TEMPERATURE,
        "attack_mode": config.ATTACK_MODE,
        "attack_type": config.ATTACK_TYPE,
        "defense_mode": config.DEFENSE_MODE,
        "task": state.get("task", ""),
        "task_id": state.get("task_id", ""),
        "trial_id": state.get("trial_id", trial),
        "proposed_action": state.get("proposed_action", ""),
        "resource_scope": state.get("resource_scope", []),
        "research_output": state.get("research_output", ""),
        "validator_approved": state.get("validator_approved", False),
        "validator_reasoning": state.get("validator_reasoning", ""),
        "action_taken": state.get("action_taken", ""),
        "attack_injected": state.get("attack_injected", False),
        "unsafe_action": state.get("unsafe_action", False),
        "policy_violation": state.get("policy_violation", False),
        "trust_hops": state.get("trust_hops", 0),
        "steps": state.get("steps", []),
    }
    with path.open("x", encoding="utf-8") as handle:
        json.dump(entry, handle, indent=2)
    print(f"[LOGGER] Saved → {filename}")
    return str(path)
