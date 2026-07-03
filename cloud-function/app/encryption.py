"""AES-256-GCM encryption utilities.

Provides authenticated encryption with associated data (AEAD).
Output format: nonce(12 bytes) || tag(16 bytes) || ciphertext

Security properties:
  - Confidentiality via AES-CTR
  - Integrity via GMAC authentication tag
  - Nonce-misuse resistance: random nonce per encryption
  - Tamper detection: ValueError on any modification
"""

import os
from Crypto.Cipher import AES

# GCM standard parameters
NONCE_LENGTH = 12  # 96-bit nonce (recommended for GCM)
TAG_LENGTH = 16    # 128-bit authentication tag
KEY_LENGTH = 32    # 256-bit key for AES-256-GCM
AAD = b"smart-ai-home-lock-v1"  # Additional authenticated data


def generate_key() -> bytes:
    """Generate a random 256-bit AES key.

    Returns:
        32 bytes suitable for AES-256-GCM
    """
    return os.urandom(KEY_LENGTH)


def aes_gcm_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data with AES-256-GCM.

    Args:
        data: Plaintext bytes to encrypt (can be empty)
        key: 32-byte AES-256 key

    Returns:
        Concatenated: nonce(12) + tag(16) + ciphertext

    Raises:
        ValueError: If key is not 32 bytes
        TypeError: If inputs are not bytes
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != KEY_LENGTH:
        raise ValueError(f"key must be {KEY_LENGTH} bytes, got {len(key)}")

    nonce = os.urandom(NONCE_LENGTH)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(AAD)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return nonce + tag + ciphertext


def aes_gcm_decrypt(packet: bytes, key: bytes) -> bytes:
    """Decrypt and verify an AES-256-GCM encrypted packet.

    Args:
        packet: nonce(12) + tag(16) + ciphertext
        key: 32-byte AES-256 key

    Returns:
        Original plaintext bytes

    Raises:
        ValueError: If authentication fails (tampered data, wrong key)
        ValueError: If packet or key is invalid length
        TypeError: If inputs are not bytes
    """
    if not isinstance(packet, bytes):
        raise TypeError("packet must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != KEY_LENGTH:
        raise ValueError(f"key must be {KEY_LENGTH} bytes, got {len(key)}")
    if len(packet) < NONCE_LENGTH + TAG_LENGTH:
        raise ValueError(
            f"packet too short: {len(packet)} < {NONCE_LENGTH + TAG_LENGTH}"
        )

    nonce = packet[:NONCE_LENGTH]
    tag = packet[NONCE_LENGTH:NONCE_LENGTH + TAG_LENGTH]
    ciphertext = packet[NONCE_LENGTH + TAG_LENGTH:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(AAD)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError(
            "AES-GCM decryption failed: data tampered or wrong key"
        ) from e

    return plaintext
