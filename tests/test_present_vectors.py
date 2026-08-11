from __future__ import annotations

import unittest

from app.crypto.present import PRESENT


class PresentVectorTests(unittest.TestCase):
    def test_published_present_80_vectors(self) -> None:
        vectors = (
            ("0000000000000000", "00000000000000000000", "5579c1387b228445"),
            ("0000000000000000", "ffffffffffffffffffff", "e72c46c0f5945049"),
            ("ffffffffffffffff", "00000000000000000000", "a112ffc72f68417b"),
            ("ffffffffffffffff", "ffffffffffffffffffff", "3333dcd3213210d2"),
        )

        for plaintext_hex, key_hex, ciphertext_hex in vectors:
            with self.subTest(plaintext=plaintext_hex, key=key_hex):
                plaintext = bytes.fromhex(plaintext_hex)
                cipher = PRESENT(bytes.fromhex(key_hex), key_size=10)
                ciphertext = cipher.encrypt_block(plaintext)

                self.assertEqual(ciphertext.hex(), ciphertext_hex)
                self.assertEqual(cipher.decrypt_block(ciphertext), plaintext)

    def test_present_128_key_schedule_reference_values(self) -> None:
        cipher = PRESENT(
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            key_size=16,
        )

        self.assertEqual(cipher._round_keys[0], 0x0011223344556677)
        self.assertEqual(cipher._round_keys[31], 0x091989A5AE8EAB21)

    def test_present_128_round_trip(self) -> None:
        plaintext = bytes.fromhex("0123456789abcdef")
        cipher = PRESENT(
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            key_size=16,
        )

        ciphertext = cipher.encrypt_block(plaintext)

        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(cipher.decrypt_block(ciphertext), plaintext)


if __name__ == "__main__":
    unittest.main()
