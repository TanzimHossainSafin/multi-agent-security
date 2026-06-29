import config
from agents.state import AgentState


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
    action = f"EXECUTED: {state['task']}"
    print(f"[EXECUTOR] {'UNSAFE' if unsafe else 'Legitimate'} execution")
    print(f"[EXECUTOR] {action}")
    return {"action_taken": action, "unsafe_action": unsafe, "steps": steps}
