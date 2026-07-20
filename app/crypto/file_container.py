from __future__ import annotations

import hashlib
import json
import struct

from dataclasses import dataclass
from pathlib import Path


MAGIC = b"TTWC"
VERSION = 1
MAX_HEADER_BYTES = 64 * 1024
HEADER_PREFIX = struct.Struct(">4sI")


class CiphertextFormatError(ValueError):
    """Raised when a ciphertext package is malformed or unsupported."""


@dataclass(frozen=True)
class CiphertextPackage:
    algorithm: str
    original_name: str
    original_size: int
    plaintext_sha256: str
    ciphertext: bytes

    def verify_plaintext(self, plaintext: bytes) -> bool:
        return hashlib.sha256(plaintext).hexdigest() == self.plaintext_sha256


def build_ciphertext_package(
    *,
    algorithm: str,
    original_name: str,
    plaintext: bytes,
    ciphertext: bytes,
) -> bytes:
    metadata = {
        "algorithm": algorithm.upper(),
        "original_name": Path(original_name).name,
        "original_size": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "version": VERSION,
    }
    header = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return HEADER_PREFIX.pack(MAGIC, len(header)) + header + ciphertext


def parse_ciphertext_package(data: bytes) -> CiphertextPackage:
    if len(data) < HEADER_PREFIX.size:
        raise CiphertextFormatError("The selected file is not a valid TTW ciphertext package.")

    magic, header_size = HEADER_PREFIX.unpack_from(data)
    if magic != MAGIC:
        raise CiphertextFormatError("The selected file is not a TTW ciphertext package.")
    if header_size <= 0 or header_size > MAX_HEADER_BYTES:
        raise CiphertextFormatError("The ciphertext package has an invalid header size.")

    payload_offset = HEADER_PREFIX.size + header_size
    if payload_offset > len(data):
        raise CiphertextFormatError("The ciphertext package header is incomplete.")

    try:
        metadata = json.loads(data[HEADER_PREFIX.size:payload_offset].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CiphertextFormatError("The ciphertext package header is damaged.") from exc

    required = {"algorithm", "original_name", "original_size", "plaintext_sha256", "version"}
    if not isinstance(metadata, dict) or not required.issubset(metadata):
        raise CiphertextFormatError("The ciphertext package header is incomplete.")
    if metadata["version"] != VERSION:
        raise CiphertextFormatError(
            f"Unsupported ciphertext package version: {metadata['version']}"
        )
    if not isinstance(metadata["algorithm"], str) or not metadata["algorithm"]:
        raise CiphertextFormatError("The ciphertext package algorithm is invalid.")
    if not isinstance(metadata["original_name"], str):
        raise CiphertextFormatError("The ciphertext package filename is invalid.")
    if not isinstance(metadata["original_size"], int) or metadata["original_size"] < 0:
        raise CiphertextFormatError("The ciphertext package original size is invalid.")
    digest = metadata["plaintext_sha256"]
    if not isinstance(digest, str) or len(digest) != 64:
        raise CiphertextFormatError("The ciphertext package verification value is invalid.")

    return CiphertextPackage(
        algorithm=metadata["algorithm"].upper(),
        original_name=Path(metadata["original_name"]).name,
        original_size=metadata["original_size"],
        plaintext_sha256=digest,
        ciphertext=data[payload_offset:],
    )
