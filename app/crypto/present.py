from __future__ import annotations

from app.crypto.base import BlockCipher, CipherError

# PRESENT S-Box
SBOX = [
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2,
]

# Inverse S-Box
SBOX_INV = [0] * 16
for i, v in enumerate(SBOX):
    SBOX_INV[v] = i


class PRESENT(BlockCipher):
    """
    PRESENT block cipher implementation.

    Supports:
    - 64-bit block size
    - 80-bit key
    - 128-bit key
    """

    DEFAULT_ROUNDS = 31

    def __init__(
        self,
        key: bytes,
        block_size: int = 8,
        key_size: int = 10,
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

        if self.block_size != 8:
            raise CipherError(
                "PRESENT supports 64-bit blocks only (block_size=8)"
            )

        if self.key_size not in (10, 16):
            raise CipherError(
                "PRESENT key_size must be 10 bytes (80-bit) or 16 bytes (128-bit)"
            )

        if len(self.key) != self.key_size:
            raise CipherError("Invalid key length")

        if self.rounds <= 0:
            raise CipherError("Rounds must be positive")

        self._round_keys = self._generate_round_keys()

    # ============================================================
    # Key Schedule
    # ============================================================

    def _generate_round_keys(self) -> list[int]:
        if self.key_size == 10:
            return self._round_keys_80()

        return self._round_keys_128()

    def _round_keys_80(self) -> list[int]:
        key_reg = int.from_bytes(self.key, "big")
        round_keys: list[int] = []

        # PRESENT requires rounds + 1 round keys
        for round_idx in range(1, self.rounds + 2):

            # Extract round key (leftmost 64 bits)
            round_keys.append(
                (key_reg >> 16) & ((1 << 64) - 1)
            )

            # Skip update after final whitening key
            if round_idx == self.rounds + 1:
                break

            # Rotate left by 61 bits
            key_reg = (
                ((key_reg << 61) & ((1 << 80) - 1))
                | (key_reg >> 19)
            )

            # Apply S-Box to MSbits
            top_nibble = (key_reg >> 76) & 0xF

            key_reg = (
                (key_reg & ((1 << 76) - 1))
                | (SBOX[top_nibble] << 76)
            )

            # XOR round counter
            key_reg ^= (round_idx & 0x1F) << 15

        return round_keys

    def _round_keys_128(self) -> list[int]:
        key_reg = int.from_bytes(self.key, "big")
        round_keys: list[int] = []

        for round_idx in range(1, self.rounds + 2):

            # Extract leftmost 64 bits
            round_keys.append(
                (key_reg >> 64) & ((1 << 64) - 1)
            )

            if round_idx == self.rounds + 1:
                break

            # Rotate left by 61 bits
            key_reg = (
                ((key_reg << 61) & ((1 << 128) - 1))
                | (key_reg >> 67)
            )

            # Apply S-Box to highest 8 bits
            high_4 = (key_reg >> 124) & 0xF
            next_4 = (key_reg >> 120) & 0xF

            key_reg &= (1 << 120) - 1

            key_reg |= SBOX[high_4] << 124
            key_reg |= SBOX[next_4] << 120

            # XOR round counter
            key_reg ^= (round_idx & 0x1F) << 62

        return round_keys

    # ============================================================
    # S-Box Layer
    # ============================================================

    @staticmethod
    def _sbox_layer(state: int) -> int:
        out = 0

        for i in range(16):
            nibble = (state >> (i * 4)) & 0xF
            out |= SBOX[nibble] << (i * 4)

        return out

    @staticmethod
    def _sbox_layer_inv(state: int) -> int:
        out = 0

        for i in range(16):
            nibble = (state >> (i * 4)) & 0xF
            out |= SBOX_INV[nibble] << (i * 4)

        return out

    # ============================================================
    # Permutation Layer
    # ============================================================

    @staticmethod
    def _p_layer(state: int) -> int:
        out = 0

        for bit in range(63):
            dst = (16 * bit) % 63
            out |= ((state >> bit) & 1) << dst

        # Preserve MSB
        out |= ((state >> 63) & 1) << 63

        return out

    @staticmethod
    def _p_layer_inv(state: int) -> int:
        out = 0

        for bit in range(63):
            src = (16 * bit) % 63
            out |= ((state >> src) & 1) << bit

        out |= ((state >> 63) & 1) << 63

        return out

    # ============================================================
    # Encryption
    # ============================================================

    def encrypt_block(self, block: bytes) -> bytes:

        if len(block) != 8:
            raise CipherError("PRESENT block must be 8 bytes")

        state = int.from_bytes(block, "big")

        # 31 rounds
        for round_idx in range(self.rounds):

            # AddRoundKey
            state ^= self._round_keys[round_idx]

            # Final round does not apply S/P layers
            if round_idx != self.rounds - 1:
                state = self._sbox_layer(state)
                state = self._p_layer(state)

        # Final whitening key
        state ^= self._round_keys[self.rounds]

        return state.to_bytes(8, "big")

    # ============================================================
    # Decryption
    # ============================================================

    def decrypt_block(self, block: bytes) -> bytes:

        if len(block) != 8:
            raise CipherError("PRESENT block must be 8 bytes")

        state = int.from_bytes(block, "big")

        # Remove final whitening key
        state ^= self._round_keys[self.rounds]

        for round_idx in range(self.rounds - 1, -1, -1):

            # Reverse AddRoundKey
            state ^= self._round_keys[round_idx]

            if round_idx != 0:
                state = self._p_layer_inv(state)
                state = self._sbox_layer_inv(state)

        return state.to_bytes(8, "big")