"""Run attacks through signature and validator-integrity defenses."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

attack_arg = sys.argv[1] if len(sys.argv) > 1 else "hijack"
if attack_arg not in ("memory", "hijack"):
    raise SystemExit("Usage: python experiments/defense_run.py [memory|hijack]")

import config

config.ATTACK_MODE = True
config.ATTACK_TYPE = attack_arg
config.DEFENSE_MODE = True

from evaluation.logger import log_run
from experiments.tasks import TASKS
from main import INITIAL_STATE, build_graph


def run_defense() -> None:
    """Execute and log the selected attack with defenses enabled."""
    app = build_graph()
    print(f"[DEFENSE] Starting {config.TRIAL_COUNT} {attack_arg} trials")
    for trial, task in enumerate(TASKS[:config.TRIAL_COUNT], 1):
        result = app.invoke({**INITIAL_STATE, "task": task, "attack_type": attack_arg})
        log_run(result, trial)
    print("[DEFENSE] Complete")


if __name__ == "__main__":
    run_defense()
