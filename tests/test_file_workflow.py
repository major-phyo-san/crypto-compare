from __future__ import annotations

import unittest

from pathlib import Path
from types import SimpleNamespace

from app.crypto.file_container import (
    CiphertextFormatError,
    build_ciphertext_package,
    parse_ciphertext_package,
)
from app.presentation.qt.main_window import (
    ALGORITHM_CONFIGS,
    FileOperationWorker,
    add_algorithm_to_recovered_path,
)


class FileWorkflowTests(unittest.TestCase):
    key = b"shared-key-128!!"
    cpu_profile = SimpleNamespace(idle_watts=5.0, tdp_watts=15.0)

    def run_operation(self, operation: str, data: bytes, algorithm: str) -> bytes:
        worker = FileOperationWorker(
            operation=operation,
            data=data,
            algorithm=algorithm,
            key=self.key,
            iterations=1,
            cpu_profile=self.cpu_profile,
        )
        output, metrics = worker._run_operation()
        self.assertGreaterEqual(metrics["time_ms"], 0)
        return output

    def test_package_round_trip_for_every_algorithm(self) -> None:
        plaintext = b"binary payload with trailing zeros\x00\x00"

        for algorithm in ALGORITHM_CONFIGS:
            with self.subTest(algorithm=algorithm):
                ciphertext = self.run_operation("encrypt", plaintext, algorithm)
                package_data = build_ciphertext_package(
                    algorithm=algorithm,
                    original_name="sample.bin",
                    plaintext=plaintext,
                    ciphertext=ciphertext,
                )
                package = parse_ciphertext_package(package_data)
                padded_plaintext = self.run_operation(
                    "decrypt", package.ciphertext, package.algorithm
                )
                recovered = padded_plaintext[: package.original_size]

                self.assertEqual(recovered, plaintext)
                self.assertTrue(package.verify_plaintext(recovered))

    def test_empty_file_round_trip(self) -> None:
        ciphertext = self.run_operation("encrypt", b"", "AES")
        package = parse_ciphertext_package(
            build_ciphertext_package(
                algorithm="AES",
                original_name="empty.bin",
                plaintext=b"",
                ciphertext=ciphertext,
            )
        )
        padded_plaintext = self.run_operation("decrypt", package.ciphertext, "AES")

        self.assertEqual(padded_plaintext[: package.original_size], b"")
        self.assertTrue(package.verify_plaintext(b""))

    def test_invalid_package_is_rejected(self) -> None:
        with self.assertRaisesRegex(CiphertextFormatError, "SDCC"):
            parse_ciphertext_package(b"not a ciphertext package")

    def test_wrong_key_fails_plaintext_verification(self) -> None:
        plaintext = b"wrong key test"
        ciphertext = self.run_operation("encrypt", plaintext, "AES")
        package = parse_ciphertext_package(
            build_ciphertext_package(
                algorithm="AES",
                original_name="sample.bin",
                plaintext=plaintext,
                ciphertext=ciphertext,
            )
        )
        worker = FileOperationWorker(
            operation="decrypt",
            data=package.ciphertext,
            algorithm="AES",
            key=b"another-key-128!",
            iterations=1,
            cpu_profile=self.cpu_profile,
        )
        padded_plaintext, _ = worker._run_operation()
        recovered = padded_plaintext[: package.original_size]

        self.assertFalse(package.verify_plaintext(recovered))

    def test_recovered_filename_contains_algorithm(self) -> None:
        self.assertEqual(
            add_algorithm_to_recovered_path(Path("recovered_report.pdf"), "AES"),
            Path("recovered_report.aes.pdf"),
        )
        self.assertEqual(
            add_algorithm_to_recovered_path(Path("recovered_report.speck.pdf"), "SPECK"),
            Path("recovered_report.speck.pdf"),
        )


if __name__ == "__main__":
    unittest.main()
