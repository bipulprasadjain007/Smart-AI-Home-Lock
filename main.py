"""Retired repository-root entrypoint.

The production Functions Framework entrypoint is ``cloud-function/main.py``.
This file remains only as a migration guard so an old command cannot start the
former unauthenticated, AES-ECB API by accident.
"""

from __future__ import annotations

import sys


MIGRATION_MESSAGE = (
    "The repository-root main.py entrypoint is retired and non-deployable. "
    "Use cloud-function/main.py (target: main) or cloud-function/deploy.sh. "
    "The legacy root API is intentionally disabled; migrate clients to the "
    "canonical /api/* AES-256-GCM protocol."
)


def main(_request=None):
    """Fail closed when an old deployment command targets the root module."""
    raise RuntimeError(MIGRATION_MESSAGE)


if __name__ == "__main__":
    print(MIGRATION_MESSAGE, file=sys.stderr)
    raise SystemExit(2)
