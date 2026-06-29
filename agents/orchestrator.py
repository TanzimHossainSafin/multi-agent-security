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
        return {"next": "validator", "steps": steps}
    if approved:
        return {"next": "executor", "steps": steps}
    return {"next": "__end__", "steps": steps}
