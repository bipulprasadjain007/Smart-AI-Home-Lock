"""Shared test fixtures and configuration."""

import os
import sys

# Ensure the cloud-function directory is on sys.path
# so that `from app.encryption import ...` works
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
