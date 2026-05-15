from __future__ import annotations

from app.crypto.base import BlockCipher, CipherError


# ============================================================
# AES CONSTANTS
# ============================================================

SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,
    0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,
    0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,
    0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,
    0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,
    0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,
    0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,
    0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,
    0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,
    0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,
    0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,
    0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,
    0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,
    0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,
    0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,
    0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,
    0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [
    0x01,0x02,0x04,0x08,0x10,
    0x20,0x40,0x80,0x1B,0x36
]


# ============================================================
# AES IMPLEMENTATION
# ============================================================

class AES(BlockCipher):
    """
    Pure Python AES implementation.

    Supports:
    - AES-128
    - AES-192
    - AES-256
    """

    _STANDARD_ROUNDS = {
        16: 10,
        24: 12,
        32: 14,
    }

    def __init__(
        self,
        key: bytes,
        block_size: int = 16,
        key_size: int = 16,
        rounds: int = 10,
        mode: int = BlockCipher.MODE_ECB,
    ) -> None:

        super().__init__(
            key=key,
            block_size=block_size,
            key_size=key_size,
            rounds=rounds,
            mode=mode,
        )

        if self.block_size != 16:
            raise CipherError(
                "AES supports 16-byte block size only"
            )

        if self.key_size not in self._STANDARD_ROUNDS:
            raise CipherError(
                "AES key_size must be 16, 24, or 32 bytes"
            )

        standard_rounds = self._STANDARD_ROUNDS[self.key_size]

        if self.rounds != standard_rounds:
            raise CipherError(
                f"AES rounds for key_size {self.key_size} "
                f"must be {standard_rounds}"
            )

        self._nk = self.key_size // 4
        self._nb = 4
        self._nr = self.rounds

        self._round_keys = self._expand_key()

    # ============================================================
    # KEY EXPANSION
    # ============================================================

    def _sub_word(self, word: list[int]) -> list[int]:
        return [SBOX[b] for b in word]

    @staticmethod
    def _rot_word(word: list[int]) -> list[int]:
        return word[1:] + word[:1]

    def _expand_key(self) -> list[list[int]]:

        key_symbols = list(self.key)

        words = []

        for i in range(self._nk):
            words.append(
                key_symbols[4*i:4*(i+1)]
            )

        total_words = self._nb * (self._nr + 1)

        for i in range(self._nk, total_words):

            temp = words[i - 1][:]

            if i % self._nk == 0:

                temp = self._sub_word(
                    self._rot_word(temp)
                )

                temp[0] ^= RCON[(i // self._nk) - 1]

            elif self._nk > 6 and i % self._nk == 4:
                temp = self._sub_word(temp)

            new_word = [
                words[i - self._nk][j] ^ temp[j]
                for j in range(4)
            ]

            words.append(new_word)

        round_keys = []

        for r in range(self._nr + 1):

            round_key = []

            for c in range(4):
                round_key.extend(words[r * 4 + c])

            round_keys.append(round_key)

        return round_keys

    # ============================================================
    # CORE OPERATIONS
    # ============================================================

    @staticmethod
    def _add_round_key(
        state: list[int],
        round_key: list[int]
    ) -> None:

        for i in range(16):
            state[i] ^= round_key[i]

    @staticmethod
    def _sub_bytes(state: list[int]) -> None:

        for i in range(16):
            state[i] = SBOX[state[i]]

    @staticmethod
    def _inv_sub_bytes(state: list[int]) -> None:

        for i in range(16):
            state[i] = INV_SBOX[state[i]]

    @staticmethod
    def _shift_rows(state: list[int]) -> None:

        state[1], state[5], state[9], state[13] = (
            state[5], state[9], state[13], state[1]
        )

        state[2], state[6], state[10], state[14] = (
            state[10], state[14], state[2], state[6]
        )

        state[3], state[7], state[11], state[15] = (
            state[15], state[3], state[7], state[11]
        )

    @staticmethod
    def _inv_shift_rows(state: list[int]) -> None:

        state[1], state[5], state[9], state[13] = (
            state[13], state[1], state[5], state[9]
        )

        state[2], state[6], state[10], state[14] = (
            state[10], state[14], state[2], state[6]
        )

        state[3], state[7], state[11], state[15] = (
            state[7], state[11], state[15], state[3]
        )

    @staticmethod
    def _xtime(a: int) -> int:
        return (
            ((a << 1) ^ 0x1B) & 0xFF
            if a & 0x80
            else (a << 1)
        ) & 0xFF

    def _mix_single_column(
        self,
        column: list[int]
    ) -> list[int]:

        t = column[0] ^ column[1] ^ column[2] ^ column[3]
        u = column[0]

        column[0] ^= t ^ self._xtime(column[0] ^ column[1])
        column[1] ^= t ^ self._xtime(column[1] ^ column[2])
        column[2] ^= t ^ self._xtime(column[2] ^ column[3])
        column[3] ^= t ^ self._xtime(column[3] ^ u)

        return column

    def _mix_columns(self, state: list[int]) -> None:

        for i in range(4):

            col = state[i*4:(i+1)*4]

            col = self._mix_single_column(col)

            state[i*4:(i+1)*4] = col

    def _inv_mix_columns(self, state: list[int]) -> None:

        for i in range(4):

            col = state[i*4:(i+1)*4]

            u = self._xtime(self._xtime(col[0] ^ col[2]))
            v = self._xtime(self._xtime(col[1] ^ col[3]))

            col[0] ^= u
            col[1] ^= v
            col[2] ^= u
            col[3] ^= v

            col = self._mix_single_column(col)

            state[i*4:(i+1)*4] = col

    # ============================================================
    # ENCRYPTION
    # ============================================================

    def encrypt_block(self, block: bytes) -> bytes:

        if len(block) != 16:
            raise CipherError(
                "AES block must be 16 bytes"
            )

        state = list(block)

        self._add_round_key(
            state,
            self._round_keys[0]
        )

        for round_idx in range(1, self._nr):

            self._sub_bytes(state)

            self._shift_rows(state)

            self._mix_columns(state)

            self._add_round_key(
                state,
                self._round_keys[round_idx]
            )

        self._sub_bytes(state)

        self._shift_rows(state)

        self._add_round_key(
            state,
            self._round_keys[self._nr]
        )

        return bytes(state)

    # ============================================================
    # DECRYPTION
    # ============================================================

    def decrypt_block(self, block: bytes) -> bytes:

        if len(block) != 16:
            raise CipherError(
                "AES block must be 16 bytes"
            )

        state = list(block)

        self._add_round_key(
            state,
            self._round_keys[self._nr]
        )

        for round_idx in range(
            self._nr - 1,
            0,
            -1
        ):

            self._inv_shift_rows(state)

            self._inv_sub_bytes(state)

            self._add_round_key(
                state,
                self._round_keys[round_idx]
            )

            self._inv_mix_columns(state)

        self._inv_shift_rows(state)

        self._inv_sub_bytes(state)

        self._add_round_key(
            state,
            self._round_keys[0]
        )

        return bytes(state)