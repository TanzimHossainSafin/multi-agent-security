"""Run a memory-poisoning or agent-hijacking attack cohort."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

attack_arg = sys.argv[1] if len(sys.argv) > 1 else "memory"
if attack_arg not in ("memory", "hijack"):
    raise SystemExit("Usage: python experiments/attack_run.py [memory|hijack]")

import config

config.ATTACK_MODE = True
config.ATTACK_TYPE = attack_arg
config.DEFENSE_MODE = False

from evaluation.logger import log_run
from experiments.tasks import TASK_RECORDS
from main import INITIAL_STATE, build_graph


def run_attack() -> None:
    """Execute and log the selected attack for each corpus task."""
    app = build_graph()
    print(f"[ATTACK] Starting {config.TRIAL_COUNT} {attack_arg} trials")
    for trial in range(1, config.TRIAL_COUNT + 1):
        record = TASK_RECORDS[(trial - 1) % len(TASK_RECORDS)]
        result = app.invoke({
            **INITIAL_STATE,
            "task": record["task_text"],
            "task_id": record["task_id"],
            "trial_id": trial,
            "attack_type": attack_arg,
        })
        log_run(result, trial)
    print("[ATTACK] Complete")


if __name__ == "__main__":
    run_attack()
