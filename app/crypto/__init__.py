"""Unified block cipher APIs for AES, PRESENT, and SPECK."""

from app.crypto.aes import AES
from app.crypto.base import BlockCipher, CipherConfig, CipherError
from app.crypto.present import PRESENT
from app.crypto.speck import SPECK

CIPHER_REGISTRY = {
    "AES": AES,
    "PRESENT": PRESENT,
    "SPECK": SPECK,
}


def create_cipher(
    algorithm: str,
    key: bytes,
    *,
    block_size: int,
    key_size: int,
    rounds: int,
    mode: int = BlockCipher.MODE_ECB,
) -> BlockCipher:
    algo_name = algorithm.upper()
    if algo_name not in CIPHER_REGISTRY:
        available = ", ".join(sorted(CIPHER_REGISTRY))
        raise CipherError(f"Unsupported algorithm '{algorithm}'. Available: {available}")
    cipher_cls = CIPHER_REGISTRY[algo_name]
    return cipher_cls.new(
        key,
        mode=mode,
        block_size=block_size,
        key_size=key_size,
        rounds=rounds,
    )


__all__ = [
    "AES",
    "PRESENT",
    "SPECK",
    "BlockCipher",
    "CipherConfig",
    "CipherError",
    "CIPHER_REGISTRY",
    "create_cipher",
]
