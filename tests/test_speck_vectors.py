from __future__ import annotations

import unittest

from app.crypto.speck import SPECK


class SpeckVectorTests(unittest.TestCase):
    def test_published_speck_128_128_vector(self) -> None:
        plaintext = bytes.fromhex("206d616465206974206571756976616c")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        expected_ciphertext = bytes.fromhex(
            "180d575cdffe60786532787951985da6"
        )
        cipher = SPECK(key)

        ciphertext = cipher.encrypt_block(plaintext)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(cipher.decrypt_block(ciphertext), plaintext)

    def test_published_round_keys(self) -> None:
        cipher = SPECK(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))

        self.assertEqual(cipher._round_keys[0], 0x0706050403020100)
        self.assertEqual(cipher._round_keys[1], 0x37253B31171D0309)
        self.assertEqual(cipher._round_keys[31], 0x2199C870DB8EC93F)


if __name__ == "__main__":
    unittest.main()
