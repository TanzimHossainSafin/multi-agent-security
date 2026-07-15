import secrets

from agents.state import AgentState


def supervisor(state: AgentState) -> dict:
    """Route deterministically so every trust transition is auditable."""
    steps = list(state.get("steps", []))
    steps.append("supervisor")

    research_done = bool(state.get("research_output", "").strip())
    reasoning_present = bool(state.get("validator_reasoning", "").strip())
    approved = state.get("validator_approved", False)

    if not research_done:
        return {"next": "researcher", "steps": steps}
    if not reasoning_present:
        # Issue a fresh review challenge here, outside the Validator's own
        # control, so the memory-poisoning defense (agents/validator_agent.py)
        # can verify a signed attestation of it later -- a compromised node
        # that bypasses real review never computes a valid one, without the
        # defense needing to read config.ATTACK_TYPE to know that.
        return {"next": "validator", "steps": steps, "review_challenge": secrets.token_hex(16)}
    if approved:
        return {"next": "executor", "steps": steps}
    return {"next": "__end__", "steps": steps}
