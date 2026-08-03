#!/usr/bin/env python3
"""Host-only check for the approved v2 canonical request and body envelope."""

import hashlib
import hmac
import json
from pathlib import Path


def main() -> None:
    vector_path = Path(__file__).resolve().parents[1] / "test" / "golden_vectors.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    body = bytes.fromhex(vector["body_hex"])

    assert len(body) >= 12 + 16, "fixture must have nonce || tag || ciphertext"
    assert len(body[:12]) == 12
    assert len(body[12:28]) == 16
    assert hashlib.sha256(body).hexdigest() == vector["body_sha256"]

    canonical = (
        "SAHL-V2\nPOST\n/api/unlock\n\n"
        f"{vector['device_id']}\n{vector['timestamp']}\n"
        f"{vector['request_nonce']}\n{vector['body_sha256']}"
    )
    assert canonical == vector["canonical"]

    signature = hmac.new(
        bytes.fromhex(vector["hmac_key_hex"]),
        canonical.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    assert signature == vector["signature"]
    assert vector["request_nonce"] == vector["request_nonce"].lower()
    assert len(vector["request_nonce"]) == 32

    aes_vector = json.loads(
        (vector_path.parent / "aes_gcm_vector.json").read_text(encoding="utf-8")
    )
    assert aes_vector["aad"] == "smart-ai-home-lock-v1"
    assert len(bytes.fromhex(aes_vector["key_hex"])) == 32
    assert len(bytes.fromhex(aes_vector["nonce_hex"])) == 12
    assert len(bytes.fromhex(aes_vector["tag_hex"])) == 16
    assert len(bytes.fromhex(aes_vector["ciphertext_hex"])) == len(
        bytes.fromhex(aes_vector["plaintext_hex"])
    )
    assert (
        aes_vector["nonce_hex"]
        + aes_vector["tag_hex"]
        + aes_vector["ciphertext_hex"]
        == aes_vector["packet_hex"]
    )
    print("protocol and AES-GCM fixture checks: PASS")


if __name__ == "__main__":
    main()
