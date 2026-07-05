from __future__ import annotations

import time
import tracemalloc

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QProgressBar,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.crypto import BlockCipher, CipherError, create_cipher
from app.system import CPUProfile, detect_cpu_profile


class CompareWorker(QObject):
    MAX_SAMPLE_BYTES = 512 * 1024

    progress = pyqtSignal(int)
    finished = pyqtSignal(list, int, str, bool)
    failed = pyqtSignal(str)

    def __init__(
        self,
        raw_data: bytes,
        iterations: int,
        file_name: str,
        cpu_profile: CPUProfile,
        mode: int = BlockCipher.MODE_ECB,
    ) -> None:
        super().__init__()
        self.raw_data = raw_data
        self.iterations = iterations
        self.file_name = file_name
        self.cpu_profile = cpu_profile
        self.mode = mode

    def run(self) -> None:
        algo_configs = [
            {"algorithm": "AES", "block_size": 16, "key_size": 16, "rounds": 10, "key": b"A" * 16},
            {
                "algorithm": "PRESENT",
                "block_size": 8,
                "key_size": 16,
                "rounds": 31,
                "key": b"PRESENT-KEY-128!",
            },
        ]
        rows: list[tuple[str, float, float, float, int, float, float]] = []
        sampled = False
        total_steps = max(1, len(algo_configs) * self.iterations * 2)
        completed_steps = 0

        try:
            for idx, config in enumerate(algo_configs, start=1):
                def on_step() -> None:
                    nonlocal completed_steps
                    completed_steps += 1
                    self.progress.emit(min(99, int((completed_steps / total_steps) * 100)))

                metrics = self._benchmark_algorithm(
                    raw_data=self.raw_data,
                    iterations=self.iterations,
                    algorithm=config["algorithm"],
                    key=config["key"],
                    block_size=config["block_size"],
                    key_size=config["key_size"],
                    rounds=config["rounds"],
                    cpu_idle_watts=self.cpu_profile.idle_watts,
                    cpu_tdp_watts=self.cpu_profile.tdp_watts,
                    mode=self.mode,
                    progress_callback=on_step,
                )
                rows.append(
                    (
                        config["algorithm"],
                        metrics["enc_ms"],
                        metrics["dec_ms"],
                        metrics["throughput_mb_s"],
                        metrics["memory_kb"],
                        metrics["cpu_usage_pct"],
                        metrics["energy_j"],
                    )
                )
                sampled = sampled or bool(metrics["used_sampling"])
                self.progress.emit(min(99, int((completed_steps / total_steps) * 100)))
        except CipherError as exc:
            self.failed.emit(str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"Unexpected error: {exc}")
            return

        self.progress.emit(100)
        self.finished.emit(rows, self.iterations, self.file_name, sampled)

    @staticmethod
    def _benchmark_algorithm(
        *,
        raw_data: bytes,
        iterations: int,
        algorithm: str,
        key: bytes,
        block_size: int,
        key_size: int,
        rounds: int,
        cpu_idle_watts: float,
        cpu_tdp_watts: float,
        mode: int = BlockCipher.MODE_ECB,
        progress_callback: Callable[[], None] | None = None,
    ) -> dict[str, float | int | bool]:
        cipher = create_cipher(
            algorithm=algorithm,
            key=key,
            mode=mode,
            block_size=block_size,
            key_size=key_size,
            rounds=rounds,
        )
        blocks = CompareWorker._split_blocks(raw_data, block_size)
        max_blocks = max(1, CompareWorker.MAX_SAMPLE_BYTES // block_size)
        used_sampling = len(blocks) > max_blocks
        if used_sampling:
            blocks = blocks[:max_blocks]

        peak_mem_encrypt = 0
        enc_start = time.perf_counter()
        cpu_enc_start = time.process_time()
        encrypted: list[bytes] = []
        tracemalloc.start()
        try:
            for _ in range(iterations):
                encrypted = [cipher.encrypt(block) for block in blocks]
                if progress_callback is not None:
                    progress_callback()
            _, peak_mem_encrypt = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        enc_ms = (time.perf_counter() - enc_start) * 1000
        cpu_enc = time.process_time() - cpu_enc_start

        peak_mem_decrypt = 0
        dec_start = time.perf_counter()
        cpu_dec_start = time.process_time()
        tracemalloc.start()
        try:
            for _ in range(iterations):
                _ = [cipher.decrypt(block) for block in encrypted]
                if progress_callback is not None:
                    progress_callback()
            _, peak_mem_decrypt = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        dec_ms = (time.perf_counter() - dec_start) * 1000
        cpu_dec = time.process_time() - cpu_dec_start

        total_seconds = max((enc_ms + dec_ms) / 1000, 1e-9)
        total_bytes = len(blocks) * block_size * iterations
        throughput_mb_s = (total_bytes / (1024 * 1024)) / total_seconds
        cpu_usage_pct = min(100.0, ((cpu_enc + cpu_dec) / total_seconds) * 100)
        peak_memory_bytes = max(peak_mem_encrypt, peak_mem_decrypt)
        memory_kb = max(1, int(peak_memory_bytes / 1024))
        modeled_power_watts = cpu_idle_watts + ((cpu_usage_pct / 100.0) * (cpu_tdp_watts - cpu_idle_watts))
        energy_j = modeled_power_watts * total_seconds

        return {
            "enc_ms": round(enc_ms, 3),
            "dec_ms": round(dec_ms, 3),
            "throughput_mb_s": round(throughput_mb_s, 3),
            "memory_kb": memory_kb,
            "cpu_usage_pct": round(cpu_usage_pct, 2),
            "modeled_power_watts": round(modeled_power_watts, 3),
            "energy_j": energy_j,
            "used_sampling": used_sampling,
        }

    @staticmethod
    def _split_blocks(data: bytes, block_size: int) -> list[bytes]:
        if not data:
            data = b"\x00" * block_size
        remainder = len(data) % block_size
        if remainder:
            data += b"\x00" * (block_size - remainder)
        return [data[i : i + block_size] for i in range(0, len(data), block_size)]


class MainWindow(QMainWindow):
    """Main UI shell for crypto algorithm comparison."""

    def __init__(self) -> None:
        super().__init__()
        self.selected_file_path: str | None = None
        self._worker_thread: QThread | None = None
        self._worker: CompareWorker | None = None
        self.cpu_profile = detect_cpu_profile()
        self.setWindowTitle("Crypto Compare Studio")
        self.resize(1080, 720)
        self._build_ui()

    def _build_ui(self) -> None:
        container = QWidget()
        root_layout = QVBoxLayout(container)
        root_layout.setContentsMargins(14, 14, 14, 14)
        root_layout.setSpacing(10)

        header = self._build_header()
        root_layout.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_quick_compare_tab(), "Quick Compare")
        self.tabs.addTab(self._build_history_tab(), "History & Export")
        root_layout.addWidget(self.tabs)

        self.setCentralWidget(container)

    def _build_header(self) -> QWidget:
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)

        title = QLabel("Crypto Algorithms Analysis")
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        subtitle = QLabel(
            f"AES vs PRESENT | CPU: {self.cpu_profile.model_name} | "
            f"Power: {self.cpu_profile.power_envelope_label}"
        )
        subtitle.setStyleSheet("color: #666;")
        subtitle.setToolTip(
            f"Detection source: {self.cpu_profile.detection_source}\n"
            f"TDP mapping source: {self.cpu_profile.tdp_source}\n"
            f"TDP confidence: {self.cpu_profile.tdp_confidence}\n"
            f"{self.cpu_profile.tdp_note}\n"
            f"Power envelope: {self.cpu_profile.power_envelope_label}\n"
            f"{self.cpu_profile.power_envelope_note}"
        )

        text_layout = QVBoxLayout()
        text_layout.addWidget(title)
        text_layout.addWidget(subtitle)

        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.status_label.setStyleSheet("font-weight: 500; color: #2e7d32;")

        layout.addLayout(text_layout)
        layout.addStretch()
        layout.addWidget(self.status_label)
        return frame

    def _build_quick_compare_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(10)

        controls_group = QGroupBox("Benchmark Controls")
        controls_layout = QGridLayout(controls_group)

        self.select_file_btn = QPushButton("Choose Input File")
        self.select_file_btn.clicked.connect(self._select_input_file)
        self.selected_file_label = QLabel("No file selected")
        self.selected_file_label.setStyleSheet("color: #666;")

        self.iterations_box = QSpinBox()
        self.iterations_box.setRange(1, 1000)
        self.iterations_box.setValue(30)

        # Mode selection is hidden but kept for internal use
        self.mode_box = QComboBox()
        self.mode_box.addItems(["ECB"])
        self.mode_box.setCurrentText("ECB")
        self.mode_box.setVisible(False)  # Hide the mode selection box

        self.run_all_btn = QPushButton("Run Compare")
        self.run_all_btn.clicked.connect(self._run_real_comparison)
        self.run_all_btn.setEnabled(False)

        self.progress = QProgressBar()
        self.progress.setValue(0)

        controls_layout.addWidget(QLabel("Input File"), 0, 0)
        controls_layout.addWidget(self.select_file_btn, 0, 1)
        controls_layout.addWidget(self.selected_file_label, 0, 2)
        controls_layout.addWidget(QLabel("Iterations"), 1, 0)
        controls_layout.addWidget(self.iterations_box, 1, 1)
        
        # Mode selection is hidden - create hidden widgets but don't add to layout
        # to avoid leaving empty space
        self.mode_box.setVisible(False)
        
        # Adjust layout: move run button and progress bar
        controls_layout.addWidget(self.run_all_btn, 0, 2)
        controls_layout.addWidget(self.progress, 1, 2)

        self.results_table = QTableWidget(2, 7)
        self.results_table.setHorizontalHeaderLabels(
            [
                "Algorithm",
                "Enc Time (ms)",
                "Dec Time (ms)",
                "Throughput (MB/s)",
                "Memory (KB)",
                "CPU Usage (%)",
                "Energy Est.",
            ]
        )
        self.results_table.verticalHeader().setVisible(False)

        self.summary_box = QTextEdit()
        self.summary_box.setReadOnly(True)
        self.summary_box.setPlaceholderText("Comparison insights will appear here...")

        self._history_rows: list[list[str]] = []

        layout.addWidget(controls_group)
        layout.addWidget(self.results_table, stretch=2)
        # layout.addWidget(self.summary_box, stretch=1)
        return tab

    def _build_history_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.history_table = QTableWidget(0, 10)
        self.history_table.setHorizontalHeaderLabels(
            [
                "Run Time",
                "File",
                "Best Algo",
                "Avg Enc (ms)",
                "Avg Dec (ms)",
                "Avg Throughput (MB/s)",
                "Avg Memory (KB)",
                "Avg CPU (%)",
                "Avg Energy Est.",
                "Mode",
            ]
        )
        self.history_table.verticalHeader().setVisible(False)

        actions = QHBoxLayout()
        self.export_json_btn = QPushButton("Export JSON")
        self.export_csv_btn = QPushButton("Export CSV")
        self.clear_history_btn = QPushButton("Clear History")
        self.export_json_btn.clicked.connect(self._update_status_not_implemented)
        self.export_csv_btn.clicked.connect(self._update_status_not_implemented)
        self.clear_history_btn.clicked.connect(self._clear_history)
        actions.addWidget(self.export_json_btn)
        actions.addWidget(self.export_csv_btn)
        actions.addWidget(self.clear_history_btn)
        actions.addStretch()

        layout.addWidget(self.history_table)
        layout.addLayout(actions)
        return tab

    def _select_input_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose File for Crypto Comparison",
            "",
            "All Files (*)",
        )
        if not file_path:
            return

        self.selected_file_path = file_path
        file_name = Path(file_path).name
        self.selected_file_label.setText(file_name)
        self.selected_file_label.setToolTip(file_path)
        self.run_all_btn.setEnabled(True)
        self.status_label.setText("Input file selected")

    def _run_real_comparison(self) -> None:
        if not self.selected_file_path:
            self.status_label.setText("Choose a file before running comparison")
            return
        if self._worker_thread and self._worker_thread.isRunning():
            self.status_label.setText("Comparison is already running")
            return

        self.progress.setValue(0)
        self.status_label.setText("Running comparison...")
        self.run_all_btn.setEnabled(False)
        self.select_file_btn.setEnabled(False)

        try:
            raw_data = Path(self.selected_file_path).read_bytes()
        except OSError as exc:
            self.status_label.setText(f"Failed to read input file: {exc}")
            self.run_all_btn.setEnabled(True)
            self.select_file_btn.setEnabled(True)
            return

        iterations = self.iterations_box.value()
        file_name = Path(self.selected_file_path).name
        
        # Mode is always ECB (mode selection is hidden)
        mode = BlockCipher.MODE_ECB
        
        self._worker_thread = QThread(self)
        self._worker = CompareWorker(
            raw_data=raw_data,
            iterations=iterations,
            file_name=file_name,
            cpu_profile=self.cpu_profile,
            mode=mode
        )
        self._worker.moveToThread(self._worker_thread)

        self._worker_thread.started.connect(self._worker.run)
        self._worker.progress.connect(self.progress.setValue)
        self._worker.finished.connect(self._on_compare_finished)
        self._worker.failed.connect(self._on_compare_failed)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.failed.connect(self._worker_thread.quit)
        self._worker_thread.finished.connect(self._cleanup_worker_thread)
        self._worker_thread.start()

    def _on_compare_finished(
        self,
        rows: list[tuple[str, float, float, float, int, float, float]],
        iterations: int,
        file_name: str,
        sampled: bool,
    ) -> None:
        for row_idx, row in enumerate(rows):
            for col_idx, value in enumerate(row):
                if col_idx == 6:
                    text = self._format_energy(value)
                elif isinstance(value, float):
                    text = f"{value:.2f}"
                else:
                    text = str(value)
                self.results_table.setItem(row_idx, col_idx, QTableWidgetItem(text))

        best_algo = max(rows, key=lambda item: item[3])[0]
        
        # Mode is always ECB
        self._append_history(
            file_name=file_name,
            best_algo=best_algo,
            rows=rows,
            mode="ECB",
        )
        self.status_label.setText("Comparison complete")
        sample_note = ""
        if sampled:
            sample_kb = CompareWorker.MAX_SAMPLE_BYTES // 1024
            sample_note = f"\nLarge file detected: benchmark used first {sample_kb} KB sample."
        self.summary_box.setPlainText(
            f"File: {file_name}\n"
            f"Iterations: {iterations}\n"
            f"Best throughput: {best_algo}"
            f"{sample_note}\n"
            f"CPU profile: {self.cpu_profile.model_name}\n"
            f"TDP mapping: {self.cpu_profile.tdp_label}\n"
            f"TDP confidence: {self.cpu_profile.tdp_confidence}\n"
            f"TDP note: {self.cpu_profile.tdp_note}\n"
            f"Power envelope: {self.cpu_profile.power_envelope_label}\n"
            f"Power model: {self.cpu_profile.power_envelope_note}\n"
            "Energy source: model-based estimate from CPU utilization and elapsed time.\n"
            "All algorithms use local implementations."
        )
        self.run_all_btn.setEnabled(True)
        self.select_file_btn.setEnabled(True)

    def _on_compare_failed(self, message: str) -> None:
        self.status_label.setText(f"Comparison failed: {message}")
        self.run_all_btn.setEnabled(True)
        self.select_file_btn.setEnabled(True)

    def _cleanup_worker_thread(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None
        if self._worker_thread is not None:
            self._worker_thread.deleteLater()
            self._worker_thread = None

    def _append_history(
        self,
        *,
        file_name: str,
        best_algo: str,
        rows: list[tuple[str, float, float, float, int, float, float]],
        mode: str,
    ) -> None:
        avg_enc = round(sum(row[1] for row in rows) / len(rows), 3)
        avg_dec = round(sum(row[2] for row in rows) / len(rows), 3)
        avg_thr = round(sum(row[3] for row in rows) / len(rows), 3)
        avg_mem = round(sum(row[4] for row in rows) / len(rows), 3)
        avg_cpu = round(sum(row[5] for row in rows) / len(rows), 3)
        avg_energy_j = sum(row[6] for row in rows) / len(rows)
        row_values = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_name,
            best_algo,
            str(avg_enc),
            str(avg_dec),
            str(avg_thr),
            str(avg_mem),
            str(avg_cpu),
            self._format_energy(avg_energy_j),
            mode,
        ]
        table_row = self.history_table.rowCount()
        self.history_table.insertRow(table_row)
        for col_idx, value in enumerate(row_values):
            self.history_table.setItem(table_row, col_idx, QTableWidgetItem(value))
        self._history_rows.append(row_values)

    def _clear_history(self) -> None:
        self.history_table.setRowCount(0)
        self._history_rows.clear()
        self.status_label.setText("History cleared")

    def _update_status_not_implemented(self) -> None:
        self.status_label.setText("Export actions are not implemented yet")

    @staticmethod
    def _format_energy(energy_joules: float) -> str:
        if energy_joules >= 1.0:
            return f"{energy_joules:.3f} J"
        if energy_joules >= 1e-3:
            return f"{energy_joules * 1e3:.3f} mJ"
        return f"{energy_joules * 1e6:.3f} uJ"


