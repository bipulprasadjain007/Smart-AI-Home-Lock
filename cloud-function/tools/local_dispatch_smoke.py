#!/usr/bin/env python3
"""Exercise a real Functions Framework HTTP dispatch without Google Cloud.

This deliberately uses a tiny local target rather than importing
``cloud-function/main.py``.  The production module initialises Firebase and
InsightFace at import time, while this check is intended to run offline in CI
and to verify the Functions Framework/WSGI status, JSON body, content type, and
headers that a deployed HTTP function must preserve.
"""

from __future__ import annotations

import sys
from pathlib import Path

import functions_framework
from flask import jsonify


@functions_framework.http
def smoke_handler(request):
    response = jsonify({"ok": True, "route": "local-dispatch-smoke"})
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Smart-Lock-Smoke"] = "passed"
    return response, 200


def main() -> int:
    # create_app is the same Functions Framework application factory used by
    # the local server.  Flask's test client performs an actual WSGI dispatch;
    # no socket, GCP credential, Firebase client, or live endpoint is needed.
    application = functions_framework.create_app(
        target="smoke_handler",
        source=str(Path(__file__).resolve()),
        signature_type="http",
    )
    response = application.test_client().get("/health")

    if response.status_code != 200:
        raise AssertionError(f"expected HTTP 200, got {response.status_code}")
    if not response.is_json:
        raise AssertionError(f"expected JSON content type, got {response.content_type!r}")
    if response.get_json() != {"ok": True, "route": "local-dispatch-smoke"}:
        raise AssertionError(f"unexpected JSON body: {response.get_json()!r}")
    if response.content_type != "application/json":
        raise AssertionError(f"unexpected content type: {response.content_type!r}")
    if response.headers.get("Cache-Control") != "no-store":
        raise AssertionError("Cache-Control header was not preserved")
    if response.headers.get("X-Smart-Lock-Smoke") != "passed":
        raise AssertionError("custom response header was not preserved")

    print("Functions Framework local dispatch smoke passed (HTTP 200, JSON, headers)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
