"""Run attacks through signature and validator-integrity defenses."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

attack_arg = sys.argv[1] if len(sys.argv) > 1 else "hijack"
if attack_arg not in ("memory", "hijack", "tamper"):
    raise SystemExit("Usage: python experiments/defense_run.py [memory|hijack|tamper]")

import config

config.ATTACK_MODE = True
config.ATTACK_TYPE = attack_arg
config.DEFENSE_MODE = True

from evaluation.logger import log_run
from experiments.tasks import TASK_RECORDS
from main import INITIAL_STATE, build_graph
from security.policy import sync_from_ground_truth

# Sync first (pins the integrity signature to legitimate content), then
# tamper -- this is what lets verify_integrity() in security/policy.py
# detect the corruption instead of silently trusting it.
sync_from_ground_truth()
if attack_arg == "tamper":
    from attacks.ground_truth_tampering import tamper_policy_view
    tamper_policy_view()


def run_defense() -> None:
    """Execute and log the selected attack with defenses enabled."""
    app = build_graph()
    print(f"[DEFENSE] Starting {config.TRIAL_COUNT} {attack_arg} trials")
    for trial in range(1, config.TRIAL_COUNT + 1):
        record = TASK_RECORDS[(trial - 1) % len(TASK_RECORDS)]
        result = app.invoke({
            **INITIAL_STATE,
            "task": record["task_text"],
            "task_id": record["task_id"],
            "trial_id": trial,
            "attack_type": attack_arg,
            "attack_injected": attack_arg == "tamper",
        })
        log_run(result, trial)
    print("[DEFENSE] Complete")


if __name__ == "__main__":
    run_defense()
