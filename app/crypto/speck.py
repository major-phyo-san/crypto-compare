from __future__ import annotations

from app.crypto.base import BlockCipher, CipherError


class SPECK(BlockCipher):
    """
    SPECK block cipher implementation.

    Supports configurable:
    - block sizes
    - key sizes
    - rounds

    Default configuration:
    SPECK128/128
    """

    DEFAULT_BLOCK_SIZE = 16  # 128-bit block
    DEFAULT_KEY_SIZE = 16    # 128-bit key
    DEFAULT_ROUNDS = 32

    def __init__(
        self,
        key: bytes,
        block_size: int = DEFAULT_BLOCK_SIZE,
        key_size: int = DEFAULT_KEY_SIZE,
        rounds: int = DEFAULT_ROUNDS,
        mode: int = BlockCipher.MODE_ECB,
    ) -> None:

        super().__init__(
            key=key,
            block_size=block_size,
            key_size=key_size,
            rounds=rounds,
            mode=mode,
        )

        # ============================================================
        # Validation
        # ============================================================

        if self.block_size % 2 != 0:
            raise CipherError("SPECK block_size must be even")

        if self.rounds <= 0:
            raise CipherError("SPECK rounds must be positive")

        if len(self.key) != self.key_size:
            raise CipherError("Invalid key length")

        # ============================================================
        # Internal Parameters
        # ============================================================

        self._word_bytes = self.block_size // 2
        self._word_bits = self._word_bytes * 8

        self._mod = 1 << self._word_bits
        self._mask = self._mod - 1

        # Number of key words
        if self.key_size % self._word_bytes != 0:
            raise CipherError(
                "SPECK key_size must be divisible by block_size/2"
            )

        self._m = self.key_size // self._word_bytes

        if self._m < 2:
            raise CipherError(
                "SPECK requires at least two key words"
            )

        # Rotation constants
        self._alpha, self._beta = self._rotation_constants(
            self._word_bits
        )

        # Generate round keys
        self._round_keys = self._expand_key()

    # ============================================================
    # Rotation Constants
    # ============================================================

    @staticmethod
    def _rotation_constants(word_bits: int) -> tuple[int, int]:

        # Official SPECK constants
        if word_bits == 16:
            return 7, 2

        return 8, 3

    # ============================================================
    # Bit Rotations
    # ============================================================

    def _rol(self, value: int, shift: int) -> int:

        shift %= self._word_bits

        return (
            ((value << shift) & self._mask)
            | (value >> (self._word_bits - shift))
        )

    def _ror(self, value: int, shift: int) -> int:

        shift %= self._word_bits

        return (
            (value >> shift)
            | ((value << (self._word_bits - shift)) & self._mask)
        )

    # ============================================================
    # Key Expansion
    # ============================================================

    def _expand_key(self) -> list[int]:

        # Split key into words
        key_words = [
            int.from_bytes(
                self.key[i:i + self._word_bytes],
                "big"
            )
            for i in range(0, len(self.key), self._word_bytes)
        ][::-1]

        # First key word becomes first round key
        round_keys = [key_words[0]]

        # Remaining key words become l-list
        l_words = list(key_words[1:])

        for round_idx in range(self.rounds - 1):

            i = round_idx % len(l_words)

            # Key schedule round
            l_words[i] = (
                (
                    self._ror(l_words[i], self._alpha)
                    + round_keys[round_idx]
                ) & self._mask
            ) ^ round_idx

            next_key = (
                self._rol(round_keys[round_idx], self._beta)
                ^ l_words[i]
            )

            round_keys.append(next_key)

        return round_keys

    # ============================================================
    # Encryption
    # ============================================================

    def encrypt_block(self, block: bytes) -> bytes:

        if len(block) != self.block_size:
            raise CipherError(
                f"SPECK block must be {self.block_size} bytes"
            )

        # Split plaintext block into two words
        x = int.from_bytes(
            block[:self._word_bytes],
            "big"
        )

        y = int.from_bytes(
            block[self._word_bytes:],
            "big"
        )

        # Encryption rounds
        for round_key in self._round_keys:

            x = (
                self._ror(x, self._alpha) + y
            ) & self._mask

            x ^= round_key

            y = self._rol(y, self._beta) ^ x

        # Recombine ciphertext
        return (
            x.to_bytes(self._word_bytes, "big")
            + y.to_bytes(self._word_bytes, "big")
        )

    # ============================================================
    # Decryption
    # ============================================================

    def decrypt_block(self, block: bytes) -> bytes:

        if len(block) != self.block_size:
            raise CipherError(
                f"SPECK block must be {self.block_size} bytes"
            )

        # Split ciphertext block
        x = int.from_bytes(
            block[:self._word_bytes],
            "big"
        )

        y = int.from_bytes(
            block[self._word_bytes:],
            "big"
        )

        # Reverse rounds
        for round_key in reversed(self._round_keys):

            y = self._ror(
                y ^ x,
                self._beta
            )

            x = self._rol(
                (
                    (x ^ round_key) - y
                ) & self._mask,
                self._alpha
            )

        # Recombine plaintext
        return (
            x.to_bytes(self._word_bytes, "big")
            + y.to_bytes(self._word_bytes, "big")
        )
