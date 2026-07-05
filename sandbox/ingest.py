"""Populate the sandbox for whichever domain is active in config.ACTIVE_DOMAIN."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
from sandbox.domains import get_domain

if __name__ == "__main__":
    get_domain(config.ACTIVE_DOMAIN).ingest()
