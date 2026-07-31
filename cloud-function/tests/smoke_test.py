#!/usr/bin/env python3
"""Production smoke test: register + unlock against local server.

Run directly: python tests/smoke_test.py
Not intended for pytest collection. Pytest will skip automatically.
"""
import os, io, json, sys
from pathlib import Path

import pytest

# Skip during pytest collection — this is a standalone script
pytestmark = pytest.mark.skip(reason="smoke_test is a standalone script, requires running server")


def _run_smoke():
    """Main smoke test logic (run only via __main__)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    os.chdir(str(Path(__file__).resolve().parent.parent))

    from dotenv import load_dotenv
    load_dotenv()

    import requests
    from app.encryption import aes_gcm_encrypt

    key = bytes.fromhex(os.environ["AES_KEY"])
    BASE_URL = "http://localhost:8080"

    # --- Health ---
    r = requests.get(f"{BASE_URL}/api/health")
    print(f"=== Health: {r.status_code} {r.json()} ===\n")

    # --- Encrypt 5 images ---
    encrypted_images = {}
    for i in range(5):
        path = f"/tmp/face{i}.jpg"
        with open(path, "rb") as f:
            plain = f.read()
        enc = aes_gcm_encrypt(plain, key)
        encrypted_images[f"image{i+1}"] = io.BytesIO(enc)
        print(f"Image {i+1}: plain={len(plain)}B -> enc={len(enc)}B")

    # --- Register ---
    print("\n=== POST /api/register ===")
    files = {k: (f"face_{k}.jpg", v.getvalue(), "image/jpeg") for k, v in encrypted_images.items()}
    r = requests.post(f"{BASE_URL}/api/register", files=files, data={"user_id": "test_user_001"})
    print(f"Status: {r.status_code}")
    print(f"Body: {json.dumps(r.json(), indent=2)}")

    # --- Unlock (use face 1) ---
    print("\n=== POST /api/unlock ===")
    with open("/tmp/face0.jpg", "rb") as f:
        plain_unlock = f.read()
    enc_unlock = aes_gcm_encrypt(plain_unlock, key)
    r = requests.post(f"{BASE_URL}/api/unlock", data=enc_unlock)
    print(f"Status: {r.status_code}")
    print(f"Body: {json.dumps(r.json(), indent=2)}")


if __name__ == "__main__":
    _run_smoke()
