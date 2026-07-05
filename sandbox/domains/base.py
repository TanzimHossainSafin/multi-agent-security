"""Contract every sandbox domain module must implement.

A domain owns everything specific to one dataset: how to ingest raw source
data into the sandbox, which privileged tools the Executor may invoke, how to
summarize sandbox state as evidence for the Researcher, and how to notify the
external mock service after an action runs. Swapping datasets means adding a
new `<name>_domain.py` module; agent and executor code never changes.
"""

from typing import Callable, Protocol


class Domain(Protocol):
    """Structural contract for a pluggable sandbox domain."""

    name: str
    TOOLS: dict[str, Callable[[], dict]]

    def evidence(self) -> dict:
        """Return a factual summary of current sandbox state for the Researcher."""
        ...

    def notify(self, task_id: str, result: dict) -> None:
        """Report a completed action to the domain's mock external service."""
        ...

    def ingest(self) -> None:
        """Populate the sandbox (database, filesystem, etc.) from source data."""
        ...