from __future__ import annotations

from dataclasses import dataclass


class CipherError(ValueError):
    """Raised for invalid cipher configuration or payload sizes."""


@dataclass(frozen=True)
class CipherConfig:
    block_size: int
    key_size: int
    rounds: int


class BlockCipher:
    """PyCryptodome-like base class for block ciphers."""

    MODE_ECB = 1
    block_size: int
    key_size: int
    rounds: int

    def __init__(
        self,
        key: bytes,
        block_size: int,
        key_size: int,
        rounds: int,
        mode: int = MODE_ECB,
    ) -> None:
        self._validate_sizes(key=key, block_size=block_size, key_size=key_size)
        self.key = key
        self.block_size = block_size
        self.key_size = key_size
        self.rounds = rounds
        self.mode = mode
        if self.mode != self.MODE_ECB:
            raise CipherError("Only MODE_ECB is currently supported")

    @classmethod
    def new(
        cls,
        key: bytes,
        mode: int = MODE_ECB,
        *,
        block_size: int,
        key_size: int,
        rounds: int,
    ) -> "BlockCipher":
        return cls(key=key, block_size=block_size, key_size=key_size, rounds=rounds, mode=mode)

    def encrypt(self, data: bytes) -> bytes:
        self._validate_block_payload(data)
        return self.encrypt_block(data)

    def decrypt(self, data: bytes) -> bytes:
        self._validate_block_payload(data)
        return self.decrypt_block(data)

    def encrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

    def decrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

    @staticmethod
    def _validate_sizes(*, key: bytes, block_size: int, key_size: int) -> None:
        if block_size <= 0:
            raise CipherError("block_size must be positive")
        if key_size <= 0:
            raise CipherError("key_size must be positive")
        if len(key) != key_size:
            raise CipherError(f"key must be exactly {key_size} bytes")

    def _validate_block_payload(self, data: bytes) -> None:
        if len(data) != self.block_size:
            raise CipherError(
                f"input must be exactly one block ({self.block_size} bytes), "
                f"got {len(data)} bytes"
            )
