from typing import Annotated, TypedDict

from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """Shared, auditable state passed between all graph nodes."""

    task: str
    task_id: str
    trial_id: int
    proposed_action: str
    resource_scope: list[str]
    authorization: dict
    review_challenge: str
    review_attestation: str
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
    policy_violation: bool
    would_execute: bool
    verdict_source: str
    steps: list
