"""Tests for AES-GCM encryption module.

AES-GCM must provide:
  - Confidentiality (AES-CTR inside GCM)
  - Integrity (GMAC authentication tag)
  - Nonce-reuse resistance (encrypt must fail if nonce reused)
  - Tamper detection (any ciphertext modification = ValueError)
"""

import os
import pytest
from app.encryption import aes_gcm_encrypt, aes_gcm_decrypt, generate_key

# Test vector: 256-bit key for AES-256-GCM
TEST_KEY_HEX = "dbebba31873175ba0513ff7b40304508dbebba31873175ba0513ff7b40304508"
TEST_KEY = bytes.fromhex(TEST_KEY_HEX)


class TestKeyGeneration:
    def test_generate_key_returns_32_bytes(self):
        key = generate_key()
        assert len(key) == 32

    def test_generate_key_is_random(self):
        key1 = generate_key()
        key2 = generate_key()
        assert key1 != key2


class TestEncryptDecryptRoundtrip:
    """Core contract: decrypt(encrypt(data)) == data for any data."""

    def test_roundtrip_small_data(self):
        plaintext = b"Hello, Smart AI Home Lock!"
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        decrypted = aes_gcm_decrypt(ciphertext, TEST_KEY)
        assert decrypted == plaintext

    def test_roundtrip_empty_data(self):
        plaintext = b""
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        decrypted = aes_gcm_decrypt(ciphertext, TEST_KEY)
        assert decrypted == plaintext

    def test_roundtrip_large_data(self):
        """Simulate a 100KB image payload."""
        plaintext = os.urandom(100 * 1024)
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        decrypted = aes_gcm_decrypt(ciphertext, TEST_KEY)
        assert decrypted == plaintext

    def test_roundtrip_binary_data(self):
        """Arbitrary binary including null bytes."""
        plaintext = bytes(range(256))
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        decrypted = aes_gcm_decrypt(ciphertext, TEST_KEY)
        assert decrypted == plaintext

    def test_roundtrip_unicode_string(self):
        plaintext = "🔒 Smart AI Home Lock 🏠".encode("utf-8")
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        decrypted = aes_gcm_decrypt(ciphertext, TEST_KEY)
        assert decrypted == plaintext


class TestNonDeterminism:
    """AES-GCM must be non-deterministic (random nonce each time)."""

    def test_same_plaintext_produces_different_ciphertexts(self):
        plaintext = b"test data"
        c1 = aes_gcm_encrypt(plaintext, TEST_KEY)
        c2 = aes_gcm_encrypt(plaintext, TEST_KEY)
        assert c1 != c2

    def test_different_nonce_length(self):
        """GCM nonce should be 12 bytes (96 bits)."""
        plaintext = b"test"
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        # Extracted nonce from first 12 bytes of output
        assert len(ciphertext) > 28  # 12 nonce + 16 tag + data
        assert len(ciphertext) == 28 + len(plaintext)


class TagIntegrity:
    pass


class TestIntegrityAndTamperResistance:
    """Any ciphertext modification must be detected."""

    def test_wrong_key_fails(self):
        plaintext = b"secret PIN data"
        wrong_key = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        with pytest.raises(ValueError, match="(tampered|wrong key)"):
            aes_gcm_decrypt(ciphertext, wrong_key)

    def test_tampered_ciphertext_fails(self):
        plaintext = b"sensitive payload"
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        tampered = bytearray(ciphertext)
        # Flip a bit in the ciphertext portion (after 12-byte nonce + 16-byte tag)
        tampered[20] ^= 0x01
        with pytest.raises(ValueError, match="(tampered|wrong key)"):
            aes_gcm_decrypt(bytes(tampered), TEST_KEY)

    def test_tampered_nonce_fails(self):
        plaintext = b"data"
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        tampered = bytearray(ciphertext)
        tampered[5] ^= 0xFF  # corrupt nonce
        with pytest.raises(ValueError, match="(tampered|wrong key)"):
            aes_gcm_decrypt(bytes(tampered), TEST_KEY)

    def test_tampered_tag_fails(self):
        plaintext = b"critical data"
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        tampered = bytearray(ciphertext)
        tampered[25] ^= 0xFF  # corrupt the tag
        with pytest.raises(ValueError, match="(tampered|wrong key)"):
            aes_gcm_decrypt(bytes(tampered), TEST_KEY)

    def test_truncated_ciphertext_fails(self):
        plaintext = b"data"
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        with pytest.raises((ValueError, IndexError)):
            aes_gcm_decrypt(ciphertext[:10], TEST_KEY)  # way too short

    def test_empty_ciphertext_fails(self):
        with pytest.raises((ValueError, IndexError)):
            aes_gcm_decrypt(b"", TEST_KEY)


class TestEdgeCases:
    """Boundary conditions and edge cases."""

    def test_single_byte(self):
        plaintext = b"\x00"
        ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
        decrypted = aes_gcm_decrypt(ciphertext, TEST_KEY)
        assert decrypted == plaintext

    def test_all_zeros_key(self):
        """All-zeros key is valid AES key (should work)."""
        key = bytes(32)
        plaintext = b"test"
        ciphertext = aes_gcm_encrypt(plaintext, key)
        decrypted = aes_gcm_decrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_repeated_usage_same_key(self):
        """Many encrypt/decrypt cycles with same key must not degrade."""
        for i in range(100):
            plaintext = f"message_{i}".encode()
            ciphertext = aes_gcm_encrypt(plaintext, TEST_KEY)
            decrypted = aes_gcm_decrypt(ciphertext, TEST_KEY)
            assert decrypted == plaintext

    def test_different_keys_produce_different_ciphertexts(self):
        """Same plaintext with different keys should look completely different."""
        plaintext = b"fixed"
        key_a = bytes.fromhex(
            "dbebba31873175ba0513ff7b40304508dbebba31873175ba0513ff7b40304508"
        )
        key_b = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        c_a = aes_gcm_encrypt(plaintext, key_a)
        c_b = aes_gcm_encrypt(plaintext, key_b)
        assert c_a != c_b

    def test_nonce_reuse_detection(self):
        """If we manually force nonce reuse, GCM should still decrypt but
        that's a protocol violation. This test ensures the function generates
        fresh nonces (call twice, check nonces differ)."""
        plaintext = b"data"
        c1 = aes_gcm_encrypt(plaintext, TEST_KEY)
        c2 = aes_gcm_encrypt(plaintext, TEST_KEY)
        nonce1 = c1[:12]
        nonce2 = c2[:12]
        assert nonce1 != nonce2, "Nonces must be unique per encryption"

    def test_output_format(self):
        """Output must be: nonce(12 bytes) + tag(16 bytes) + ciphertext."""
        plaintext = b"hello"
        ct = aes_gcm_encrypt(plaintext, TEST_KEY)
        # 12 + 16 + len(data)
        assert len(ct) == 12 + 16 + len(plaintext)
        nonce, rest = ct[:12], ct[12:]
        tag, ciphertext = rest[:16], rest[16:]
        assert len(nonce) == 12
        assert len(tag) == 16
        # Verify decryption works
        decrypted = aes_gcm_decrypt(ct, TEST_KEY)
        assert decrypted == plaintext
