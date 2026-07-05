"""Domain registry: resolves config.ACTIVE_DOMAIN to a domain module."""

import importlib
from functools import lru_cache


@lru_cache(maxsize=None)
def get_domain(name: str):
    """Import and return the sandbox domain module registered under `name`."""
    return importlib.import_module(f"sandbox.domains.{name}_domain")