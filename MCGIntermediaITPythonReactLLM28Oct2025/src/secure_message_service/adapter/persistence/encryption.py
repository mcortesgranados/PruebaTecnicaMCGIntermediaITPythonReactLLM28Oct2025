"""Encryption utilities: AES-256-CBC with PKCS7 padding.

Provides AESEncryptionService.encrypt/decrypt and a helper to load
an encryption key from the environment variable ENCRYPTION_KEY.
"""
from __future__ import annotations

from base64 import b64encode, b64decode
from typing import Optional
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class AESEncryptionService:
    """AES encryption service using AES-CBC + PKCS7 padding.

    This implementation expects a key of 32 bytes (AES-256). The
    encrypt method returns a base64-encoded string containing IV + ciphertext.
    """

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes")
        if len(key) != 32:
            raise ValueError("Encryption key must be 32 bytes for AES-256")
        self.key = bytes(key)
        self.backend = default_backend()

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext and return base64(iv + ciphertext)."""
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext must be a string")
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        plaintext_bytes = plaintext.encode("utf-8")
        padded = padder.update(plaintext_bytes) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        return b64encode(iv + ct).decode("utf-8")

    def decrypt(self, ciphertext_b64: str) -> str:
        """Decrypt base64(iv + ciphertext) and return plaintext string."""
        if not isinstance(ciphertext_b64, str):
            raise TypeError("Ciphertext must be a base64 string")
        raw = b64decode(ciphertext_b64)
        if len(raw) <= 16:
            raise ValueError("Ciphertext too short")
        iv = raw[:16]
        ct = raw[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded_plain) + unpadder.finalize()
        return plain.decode("utf-8")


def load_encryption_key_from_env(env_key: str = "ENCRYPTION_KEY") -> bytes:
    """Load encryption key from environment.

    Accepts:
    - raw 32-byte string
    - base64-encoded key

    Raises EnvironmentError if not present or invalid length.
    """
    key = os.getenv(env_key)
    if not key:
        raise EnvironmentError(f"{env_key} not set")

    # If key length is exactly 32 when encoded as UTF-8, accept raw bytes
    try:
        candidate = key.encode("utf-8")
        if len(candidate) == 32:
            return candidate
    except Exception:
        pass

    # Otherwise try base64 decode
    try:
        decoded = b64decode(key)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    raise EnvironmentError(f"{env_key} must be a 32-byte raw string or a base64-encoded 32-byte key")

