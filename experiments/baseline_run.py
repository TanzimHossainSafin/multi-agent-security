"""Run the no-attack control cohort and persist every trial."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config

config.ATTACK_MODE = False
config.ATTACK_TYPE = "none"
config.DEFENSE_MODE = False

from evaluation.logger import log_run
from experiments.tasks import TASK_RECORDS
from main import INITIAL_STATE, build_graph
from security.policy import sync_from_ground_truth

sync_from_ground_truth()


def run_baseline() -> None:
    """Execute the configured number of baseline trials."""
    app = build_graph()
    print(f"[BASELINE] Starting {config.TRIAL_COUNT} trials")
    for trial in range(1, config.TRIAL_COUNT + 1):
        record = TASK_RECORDS[(trial - 1) % len(TASK_RECORDS)]
        result = app.invoke({
            **INITIAL_STATE,
            "task": record["task_text"],
            "task_id": record["task_id"],
            "trial_id": trial,
            "attack_type": "none",
        })
        log_run(result, trial)
    print("[BASELINE] Complete")


if __name__ == "__main__":
    run_baseline()
