"""Create a canonical AES-256-GCM packet containing a six-digit PIN.

This helper is for local/staging tooling only.  It intentionally has no
default PIN and does not implement the retired AES-ECB format.  The packet is
``nonce(12) || tag(16) || ciphertext`` with the cloud function's configured
AAD, provided by ``cloud-function/app/encryption.py``.

Examples::

    python pin.py YOUR_SIX_DIGIT_PIN
    python pin.py YOUR_SIX_DIGIT_PIN --output /tmp/pin.packet

The AES key is read from ``AES_KEY`` in the environment, or from the root
``.env`` file when present.  The key value is never printed.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent
CLOUD_FUNCTION_ROOT = ROOT / "cloud-function"
load_dotenv(ROOT / ".env")
if str(CLOUD_FUNCTION_ROOT) not in sys.path:
    sys.path.insert(0, str(CLOUD_FUNCTION_ROOT))

from app.encryption import aes_gcm_encrypt  # noqa: E402  # type: ignore[import-not-found]


def load_aes_key() -> bytes:
    """Load and validate the 32-byte hex AES key without revealing it."""

    key_hex = os.environ.get("AES_KEY", "").strip()
    if len(key_hex) != 64:
        raise ValueError("AES_KEY must be exactly 64 hexadecimal characters (32 bytes)")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise ValueError("AES_KEY must contain only hexadecimal characters") from exc
    if len(key) != 32:
        raise ValueError("AES_KEY must decode to exactly 32 bytes")
    return key


def encrypt_pin(pin: str, key: bytes) -> bytes:
    """Encrypt one explicit six-digit PIN using the cloud packet format."""

    if not isinstance(pin, str) or len(pin) != 6 or not pin.isascii() or not pin.isdigit():
        raise ValueError("PIN must be exactly six ASCII digits")
    return aes_gcm_encrypt(pin.encode("ascii"), key)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pin", help="six-digit PIN to encrypt (required; never defaults)")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "encrypted_pin.bin",
        help="output packet path (default: repository-root encrypted_pin.bin)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        packet = encrypt_pin(args.pin, load_aes_key())
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(packet)
    try:
        args.output.chmod(0o600)
    except OSError:
        # The packet was written successfully; permissions may be limited on
        # some mounted filesystems, so do not print or expose key material.
        pass
    print(f"Wrote AES-256-GCM PIN packet ({len(packet)} bytes) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
