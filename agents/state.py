from typing import Annotated, TypedDict

from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """Shared, auditable state passed between all graph nodes."""

    task: str
    task_id: str
    trial_id: int
    messages: Annotated[list, add_messages]
    research_output: str
    validator_approved: bool
    validator_reasoning: str
    action_taken: str
    next: str
    attack_injected: bool
    attack_type: str
    trust_hops: int
    unsafe_action: bool
    steps: list
