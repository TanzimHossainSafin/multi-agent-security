"""Run the no-attack control cohort and persist every trial."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config

config.ATTACK_MODE = False
config.ATTACK_TYPE = "none"
config.DEFENSE_MODE = False

from evaluation.logger import log_run
from experiments.tasks import TASKS
from main import INITIAL_STATE, build_graph


def run_baseline() -> None:
    """Execute the configured number of baseline trials."""
    app = build_graph()
    print(f"[BASELINE] Starting {config.TRIAL_COUNT} trials")
    for trial, task in enumerate(TASKS[:config.TRIAL_COUNT], 1):
        result = app.invoke({
            **INITIAL_STATE,
            "task": task,
            "task_id": f"TASK-{trial:03d}",
            "trial_id": trial,
            "attack_type": "none",
        })
        log_run(result, trial)
    print("[BASELINE] Complete")


if __name__ == "__main__":
    run_baseline()
