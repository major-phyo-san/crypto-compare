from __future__ import annotations

import csv
import json
import os
import unittest

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QFileDialog, QLabel, QLineEdit

from app.presentation.qt.main_window import HISTORY_HEADERS, MainWindow


class MainWindowUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.window = MainWindow()

    def tearDown(self) -> None:
        self.window.close()

    def test_key_visibility_toggle(self) -> None:
        self.assertEqual(self.window.key_input.echoMode(), QLineEdit.EchoMode.Password)
        self.window.show_key_box.setChecked(True)
        self.assertEqual(self.window.key_input.echoMode(), QLineEdit.EchoMode.Normal)

    def test_graph_analysis_tab_is_after_file_operations(self) -> None:
        tab_names = [
            self.window.tabs.tabText(index)
            for index in range(self.window.tabs.count())
        ]

        self.assertEqual(
            tab_names,
            ["File Operations", "Graph Analysis", "History & Export"],
        )

    def test_graph_data_keeps_latest_run_per_algorithm(self) -> None:
        first_metrics = {
            "time_ms": 10.0,
            "throughput_mb_s": 2.0,
            "memory_kb": 128,
            "cpu_usage_pct": 50.0,
            "energy_j": 1.0,
            "iterations": 1,
            "processed_bytes": 16,
            "modeled_power_watts": 5.0,
        }
        latest_metrics = dict(first_metrics, time_ms=20.0, energy_j=2.5)

        self.window._append_analysis_row(
            table=self.window.encryption_table,
            algorithm="AES",
            input_name="sample.bin",
            metrics=first_metrics,
            output_path=Path("sample.bin.aes.ttwc"),
        )
        self.window._append_analysis_row(
            table=self.window.encryption_table,
            algorithm="AES",
            input_name="sample.bin",
            metrics=latest_metrics,
            output_path=Path("sample.bin.aes.ttwc"),
        )

        self.assertEqual(
            self.window._graph_data["encrypt"]["AES"]["time_ms"],
            20.0,
        )
        self.assertEqual(
            self.window._graph_data["encrypt"]["AES"]["energy_j"],
            2.5,
        )

    def test_iterations_label_stays_close_to_input(self) -> None:
        self.window.show()
        self.app.processEvents()
        label = next(
            item for item in self.window.findChildren(QLabel) if item.text() == "Iterations"
        )
        gap = self.window.iterations_box.geometry().left() - label.geometry().right()

        self.assertGreaterEqual(gap, 0)
        self.assertLessEqual(gap, 24)

    def test_history_columns_fill_common_window_widths(self) -> None:
        history_index = next(
            index
            for index in range(self.window.tabs.count())
            if self.window.tabs.tabText(index) == "History & Export"
        )
        self.window.tabs.setCurrentIndex(history_index)
        for width in (1400, 1800):
            with self.subTest(width=width):
                self.window.resize(width, 800)
                self.window.show()
                self.app.processEvents()
                header_width = self.window.history_table.horizontalHeader().length()
                viewport_width = self.window.history_table.viewport().width()

                self.assertLessEqual(abs(header_width - viewport_width), 2)

    def test_history_exports_json_and_csv(self) -> None:
        metrics = {
            "time_ms": 1.25,
            "throughput_mb_s": 2.5,
            "memory_kb": 3,
            "cpu_usage_pct": 4.5,
            "energy_j": 0.006,
            "iterations": 1,
            "processed_bytes": 16,
            "modeled_power_watts": 5.0,
        }
        self.window._append_history(
            operation="encrypt",
            file_name="sample.bin",
            algorithm="AES",
            metrics=metrics,
            output_path=Path("sample.bin.aes.ttwc"),
        )

        with TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "history.json"
            csv_path = Path(tmp) / "history.csv"
            with patch.object(
                QFileDialog, "getSaveFileName", return_value=(str(json_path), "")
            ):
                self.window._export_history_json()
            with patch.object(
                QFileDialog, "getSaveFileName", return_value=(str(csv_path), "")
            ):
                self.window._export_history_csv()

            json_rows = json.loads(json_path.read_text(encoding="utf-8"))
            with csv_path.open(encoding="utf-8", newline="") as stream:
                csv_rows = list(csv.reader(stream))

        self.assertEqual(json_rows[0]["Algorithm"], "AES")
        self.assertEqual(tuple(csv_rows[0]), HISTORY_HEADERS)
        self.assertEqual(csv_rows[1][3], "AES")


if __name__ == "__main__":
    unittest.main()
