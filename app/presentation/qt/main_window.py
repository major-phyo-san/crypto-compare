from __future__ import annotations

import csv
import json
import time
import tracemalloc

from datetime import datetime
from pathlib import Path

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from PyQt6.QtCore import QObject, QThread, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStyle,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.crypto import BlockCipher, CipherError, create_cipher
from app.crypto.file_container import (
    CiphertextFormatError,
    CiphertextPackage,
    build_ciphertext_package,
    parse_ciphertext_package,
)
from app.system import CPUProfile, detect_cpu_profile
from app.presentation.qt.theme import APP_STYLESHEET


COMMON_KEY_SIZE_BYTES = 16
ALGORITHM_CONFIGS = {
    "AES": {"block_size": 16, "key_size": 16, "rounds": 10},
    "PRESENT": {"block_size": 8, "key_size": 16, "rounds": 31},
    "SPECK": {"block_size": 16, "key_size": 16, "rounds": 32},
}
HISTORY_HEADERS = (
    "Run Time",
    "Operation",
    "File",
    "Algorithm",
    "Iterations",
    "Time (ms)",
    "Throughput (MB/s)",
    "Memory (KB)",
    "CPU Usage (%)",
    "Energy Est.",
    "Output File",
)
ALGORITHM_COLORS = {
    "AES": "#0ea5e9",
    "PRESENT": "#f97316",
    "SPECK": "#2563eb",
}
GRAPH_METRICS = (
    ("time_ms", "Time (ms)"),
    ("throughput_mb_s", "Throughput (MB/s)"),
    ("memory_kb", "Memory (KB)"),
    ("cpu_usage_pct", "CPU Usage (%)"),
    ("energy_j", "Energy (J)"),
)


def normalize_common_key(key_text: str) -> bytes:
    key = key_text.encode("utf-8")
    if len(key) < COMMON_KEY_SIZE_BYTES:
        raise ValueError(
            "The key must be at least 16 UTF-8 bytes (128 bits). "
            "For ordinary English text, enter at least 16 characters."
        )
    return key[:COMMON_KEY_SIZE_BYTES]


def add_algorithm_to_recovered_path(path: Path, algorithm: str) -> Path:
    algorithm_suffix = f".{algorithm.lower()}"
    if path.stem.lower().endswith(algorithm_suffix):
        return path
    return path.with_name(f"{path.stem}{algorithm_suffix}{path.suffix}")


class FileOperationWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str, str, dict, bytes)
    failed = pyqtSignal(str)

    def __init__(
        self,
        *,
        operation: str,
        data: bytes,
        algorithm: str,
        key: bytes,
        iterations: int,
        cpu_profile: CPUProfile,
        mode: int = BlockCipher.MODE_ECB,
    ) -> None:
        super().__init__()
        self.operation = operation
        self.data = data
        self.algorithm = algorithm
        self.key = key
        self.iterations = iterations
        self.cpu_profile = cpu_profile
        self.mode = mode

    def run(self) -> None:
        try:
            output, metrics = self._run_operation()
        except CipherError as exc:
            self.failed.emit(str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"Unexpected error: {exc}")
            return

        self.progress.emit(100)
        self.finished.emit(self.operation, self.algorithm, metrics, output)

    def _run_operation(self) -> tuple[bytes, dict[str, float | int]]:
        if self.operation not in {"encrypt", "decrypt"}:
            raise CipherError(f"Unsupported file operation: {self.operation}")

        config = ALGORITHM_CONFIGS.get(self.algorithm)
        if config is None:
            raise CipherError(f"Unsupported algorithm: {self.algorithm}")

        cipher = create_cipher(
            algorithm=self.algorithm,
            key=self.key,
            mode=self.mode,
            block_size=config["block_size"],
            key_size=config["key_size"],
            rounds=config["rounds"],
        )
        block_size = config["block_size"]
        if self.operation == "encrypt":
            blocks = self._split_plaintext(self.data, block_size)
            transform = cipher.encrypt
        else:
            blocks = self._split_ciphertext(self.data, block_size)
            transform = cipher.decrypt

        output_blocks: list[bytes] = []
        wall_start = time.perf_counter()
        cpu_start = time.process_time()
        tracemalloc.start()
        try:
            for iteration in range(self.iterations):
                output_blocks = [transform(block) for block in blocks]
                self.progress.emit(int(((iteration + 1) / self.iterations) * 99))
            _, peak_memory_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        total_seconds = max(time.perf_counter() - wall_start, 1e-9)
        cpu_seconds = time.process_time() - cpu_start
        total_bytes = len(blocks) * block_size * self.iterations
        throughput_mb_s = (total_bytes / (1024 * 1024)) / total_seconds
        cpu_usage_pct = min(100.0, (cpu_seconds / total_seconds) * 100)
        memory_kb = max(1, int(peak_memory_bytes / 1024))
        modeled_power_watts = self.cpu_profile.idle_watts + (
            (cpu_usage_pct / 100.0)
            * (self.cpu_profile.tdp_watts - self.cpu_profile.idle_watts)
        )
        energy_j = modeled_power_watts * total_seconds

        metrics: dict[str, float | int] = {
            "time_ms": round(total_seconds * 1000, 3),
            "throughput_mb_s": round(throughput_mb_s, 3),
            "memory_kb": memory_kb,
            "cpu_usage_pct": round(cpu_usage_pct, 2),
            "modeled_power_watts": round(modeled_power_watts, 3),
            "energy_j": energy_j,
            "iterations": self.iterations,
            "processed_bytes": total_bytes,
        }
        return b"".join(output_blocks), metrics

    @staticmethod
    def _split_plaintext(data: bytes, block_size: int) -> list[bytes]:
        if not data:
            data = b"\x00" * block_size
        remainder = len(data) % block_size
        if remainder:
            data += b"\x00" * (block_size - remainder)
        return [data[i : i + block_size] for i in range(0, len(data), block_size)]

    @staticmethod
    def _split_ciphertext(data: bytes, block_size: int) -> list[bytes]:
        if not data or len(data) % block_size:
            raise CipherError(
                f"Ciphertext must contain complete {block_size}-byte blocks"
            )
        return [data[i : i + block_size] for i in range(0, len(data), block_size)]


class MetricBarChart(QWidget):
    """Matplotlib bar chart for one analysis metric."""

    def __init__(self, *, title: str, y_label: str) -> None:
        super().__init__()
        self.title = title
        self.y_label = y_label
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.figure = Figure(figsize=(3.2, 1.9), dpi=100, facecolor="#ffffff")
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.canvas.setMinimumHeight(185)
        self.canvas.setMaximumHeight(205)
        layout.addWidget(self.canvas)
        self.update_values({})

    def update_values(self, values_by_algorithm: dict[str, float]) -> None:
        self.figure.clear()
        axis = self.figure.add_subplot(111)
        axis.set_facecolor("#ffffff")
        algorithms = list(ALGORITHM_CONFIGS)
        values = [values_by_algorithm.get(algorithm, 0.0) for algorithm in algorithms]
        colors = [ALGORITHM_COLORS[algorithm] for algorithm in algorithms]

        bars = axis.bar(algorithms, values, color=colors, width=0.48)
        axis.set_title(self.title, color="#0f172a", fontsize=9.5, fontweight="bold")
        axis.set_ylabel(self.y_label, color="#475569", fontsize=8.5)
        axis.grid(axis="y", color="#e2e8f0", linewidth=0.7)
        axis.set_axisbelow(True)
        axis.tick_params(axis="x", colors="#0f172a", labelsize=8.5, length=0)
        axis.tick_params(axis="y", colors="#475569", labelsize=8)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        axis.spines["left"].set_color("#cbd5e1")
        axis.spines["bottom"].set_color("#cbd5e1")

        if any(value > 0 for value in values):
            top_value = max(values)
            axis.set_ylim(0, top_value * 1.16 if top_value > 0 else 1)
            for bar, value in zip(bars, values):
                if value <= 0:
                    continue
                label = f"{value:.3f}" if value < 1000 else f"{value:,.0f}"
                axis.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height(),
                    label,
                    ha="center",
                    va="bottom",
                    color="#0f172a",
                    fontsize=7.5,
                )
        else:
            axis.set_ylim(0, 1)
            axis.text(
                0.5,
                0.52,
                "Run algorithms to generate this graph",
                transform=axis.transAxes,
                ha="center",
                va="center",
                color="#64748b",
                fontsize=8,
            )

        self.figure.tight_layout(pad=0.9)
        self.canvas.draw_idle()


class MainWindow(QMainWindow):
    """Main UI shell for crypto algorithm comparison."""

    def __init__(self) -> None:
        super().__init__()
        self.selected_file_path: str | None = None
        self._worker_thread: QThread | None = None
        self._worker: FileOperationWorker | None = None
        self._pending_output_path: Path | None = None
        self._pending_plaintext: bytes | None = None
        self._pending_package: CiphertextPackage | None = None
        self._operation_input_name = ""
        self._graph_data: dict[str, dict[str, dict[str, float]]] = {
            "encrypt": {},
            "decrypt": {},
        }
        self._graph_charts: dict[str, dict[str, MetricBarChart]] = {
            "encrypt": {},
            "decrypt": {},
        }
        self.cpu_profile = detect_cpu_profile()
        self.setWindowTitle("Crypto Compare Studio")
        self.setWindowIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        )
        self.setMinimumSize(980, 680)
        self.resize(1180, 760)
        self.setStyleSheet(APP_STYLESHEET)
        self._build_ui()

    def _build_ui(self) -> None:
        container = QWidget()
        container.setObjectName("appRoot")
        root_layout = QVBoxLayout(container)
        root_layout.setContentsMargins(18, 18, 18, 16)
        root_layout.setSpacing(12)

        header = self._build_header()
        root_layout.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("primaryTabs")
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._build_file_operations_tab(), "File Operations")
        self.tabs.addTab(self._build_graph_analysis_tab(), "Graph Analysis")
        self.tabs.addTab(self._build_history_tab(), "History & Export")
        root_layout.addWidget(self.tabs)

        self.setCentralWidget(container)

    def _build_header(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("appHeader")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(18, 13, 16, 13)
        layout.setSpacing(14)

        title = QLabel("Crypto Compare Studio")
        title.setObjectName("appTitle")
        subtitle = QLabel(
            f"AES-128 | PRESENT-128 | SPECK-128/128   /   "
            f"{self.cpu_profile.model_name}   /   {self.cpu_profile.power_envelope_label}"
        )
        subtitle.setObjectName("appSubtitle")
        subtitle.setToolTip(
            f"Detection source: {self.cpu_profile.detection_source}\n"
            f"TDP mapping source: {self.cpu_profile.tdp_source}\n"
            f"TDP confidence: {self.cpu_profile.tdp_confidence}\n"
            f"{self.cpu_profile.tdp_note}\n"
            f"Power envelope: {self.cpu_profile.power_envelope_label}\n"
            f"{self.cpu_profile.power_envelope_note}"
        )

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        text_layout.addWidget(title)
        text_layout.addWidget(subtitle)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusBadge")
        self.status_label.setProperty("tone", "neutral")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        layout.addLayout(text_layout)
        layout.addStretch()
        layout.addWidget(self.status_label)
        return frame

    def _set_status(self, text: str, tone: str = "neutral") -> None:
        self.status_label.setText(text)
        self.status_label.setProperty("tone", tone)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def _toggle_key_visibility(self, visible: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        self.key_input.setEchoMode(mode)

    def _build_file_operations_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(12)

        controls_panel = QFrame()
        controls_panel.setObjectName("controlsPanel")
        panel_layout = QVBoxLayout(controls_panel)
        panel_layout.setContentsMargins(18, 14, 18, 16)
        panel_layout.setSpacing(12)

        section_row = QHBoxLayout()
        section_title = QLabel("File workspace")
        section_title.setObjectName("sectionTitle")
        section_meta = QLabel("128-bit common-key analysis")
        section_meta.setObjectName("sectionMeta")
        section_row.addWidget(section_title)
        section_row.addStretch()
        section_row.addWidget(section_meta)
        panel_layout.addLayout(section_row)

        controls_layout = QGridLayout()
        controls_layout.setHorizontalSpacing(12)
        controls_layout.setVerticalSpacing(10)
        panel_layout.addLayout(controls_layout)

        self.select_file_btn = QPushButton("Choose file")
        self.select_file_btn.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton)
        )
        self.select_file_btn.clicked.connect(self._select_input_file)
        self.selected_file_label = QLabel("No file selected")
        self.selected_file_label.setObjectName("fileValue")

        self.iterations_box = QSpinBox()
        self.iterations_box.setRange(1, 1000)
        self.iterations_box.setValue(30)
        self.iterations_box.setFixedWidth(108)

        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_input.setPlaceholderText("At least 16 characters for a 128-bit key")
        self.key_input.setToolTip(
            "The first 16 UTF-8 bytes are used as the common key for all algorithms."
        )
        self.show_key_box = QCheckBox("Show key")
        self.show_key_box.toggled.connect(self._toggle_key_visibility)

        self.algorithm_box = QComboBox()
        self.algorithm_box.addItems(ALGORITHM_CONFIGS)
        self.algorithm_box.setToolTip(
            "Select the algorithm used to encrypt. Decryption reads it from the ciphertext file."
        )

        self.encrypt_btn = QPushButton("Encrypt File")
        self.encrypt_btn.setObjectName("encryptButton")
        self.encrypt_btn.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.encrypt_btn.clicked.connect(self._start_encryption)
        self.encrypt_btn.setEnabled(False)

        self.decrypt_btn = QPushButton("Decrypt File")
        self.decrypt_btn.setObjectName("decryptButton")
        self.decrypt_btn.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton)
        )
        self.decrypt_btn.clicked.connect(self._start_decryption)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(False)

        controls_layout.addWidget(QLabel("Plaintext file"), 0, 0)
        controls_layout.addWidget(self.select_file_btn, 0, 1)
        controls_layout.addWidget(self.selected_file_label, 0, 2, 1, 2)
        controls_layout.addWidget(QLabel("Common key"), 1, 0)
        controls_layout.addWidget(self.key_input, 1, 1, 1, 2)
        controls_layout.addWidget(self.show_key_box, 1, 3)
        controls_layout.addWidget(QLabel("Algorithm"), 2, 0)
        controls_layout.addWidget(self.algorithm_box, 2, 1)
        controls_layout.addWidget(QLabel("Iterations"), 2, 2)
        controls_layout.addWidget(self.iterations_box, 2, 3)

        action_row = QHBoxLayout()
        action_row.setSpacing(12)
        action_row.addWidget(self.encrypt_btn, 1)
        action_row.addWidget(self.decrypt_btn, 1)
        controls_layout.addLayout(action_row, 3, 1, 1, 3)
        controls_layout.addWidget(self.progress, 4, 0, 1, 4)
        controls_layout.setColumnStretch(1, 1)
        controls_layout.setColumnStretch(2, 0)

        self.analysis_tabs = QTabWidget()
        self.analysis_tabs.setObjectName("analysisTabs")
        self.analysis_tabs.setDocumentMode(True)
        self.encryption_table = self._build_analysis_table()
        self.decryption_table = self._build_analysis_table()
        self.analysis_tabs.addTab(self.encryption_table, "Encryption Analysis")
        self.analysis_tabs.addTab(self.decryption_table, "Decryption Analysis")

        self._history_rows: list[list[str]] = []

        layout.addWidget(controls_panel)
        layout.addWidget(self.analysis_tabs, stretch=2)
        return tab

    @staticmethod
    def _build_analysis_table() -> QTableWidget:
        table = QTableWidget(0, 9)
        table.setHorizontalHeaderLabels(
            [
                "Algorithm",
                "Input File",
                "Iterations",
                "Time (ms)",
                "Throughput (MB/s)",
                "Memory (KB)",
                "CPU Usage (%)",
                "Energy Est.",
                "Output File",
            ]
        )
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(38)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setShowGrid(False)
        table.setWordWrap(False)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)
        return table

    def _build_graph_analysis_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)
        content_layout.addWidget(
            self._build_graph_section("Encryption Graphs", "encrypt")
        )
        content_layout.addWidget(
            self._build_graph_section("Decryption Graphs", "decrypt")
        )
        content_layout.addStretch()

        scroll.setWidget(content)
        layout.addWidget(scroll)
        return tab

    def _build_graph_section(self, title_text: str, operation: str) -> QWidget:
        frame = QFrame()
        frame.setObjectName("controlsPanel")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 12, 16, 14)
        layout.setSpacing(8)

        section_title = QLabel(title_text)
        section_title.setObjectName("sectionTitle")
        layout.addWidget(section_title)

        chart_grid = QGridLayout()
        chart_grid.setHorizontalSpacing(10)
        chart_grid.setVerticalSpacing(8)
        layout.addLayout(chart_grid)

        for index, (metric_key, metric_label) in enumerate(GRAPH_METRICS):
            chart = MetricBarChart(
                title=f"{title_text.replace('Graphs', '').strip()} {metric_label}",
                y_label=metric_label,
            )
            self._graph_charts[operation][metric_key] = chart
            chart_grid.addWidget(chart, index // 3, index % 3)

        return frame

    def _build_history_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.history_table = QTableWidget(0, 11)
        self.history_table.setHorizontalHeaderLabels(HISTORY_HEADERS)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.verticalHeader().setDefaultSectionSize(38)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setShowGrid(False)
        self.history_table.setWordWrap(False)
        history_header = self.history_table.horizontalHeader()
        history_header.setMinimumSectionSize(60)
        history_widths = {
            0: 150,
            1: 105,
            3: 100,
            4: 90,
            5: 100,
            6: 150,
            7: 120,
            8: 130,
            9: 105,
        }
        for column, width in history_widths.items():
            history_header.setSectionResizeMode(
                column, QHeaderView.ResizeMode.Interactive
            )
            history_header.resizeSection(column, width)
        history_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        history_header.setSectionResizeMode(10, QHeaderView.ResizeMode.Stretch)
        self.history_table.setHorizontalScrollMode(
            QAbstractItemView.ScrollMode.ScrollPerPixel
        )

        actions = QHBoxLayout()
        self.export_json_btn = QPushButton("Export JSON")
        self.export_csv_btn = QPushButton("Export CSV")
        self.clear_history_btn = QPushButton("Clear History")
        save_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        self.export_json_btn.setIcon(save_icon)
        self.export_csv_btn.setIcon(save_icon)
        self.clear_history_btn.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon)
        )
        self.export_json_btn.clicked.connect(self._export_history_json)
        self.export_csv_btn.clicked.connect(self._export_history_csv)
        self.clear_history_btn.clicked.connect(self._clear_history)
        self.export_json_btn.setEnabled(False)
        self.export_csv_btn.setEnabled(False)
        self.clear_history_btn.setEnabled(False)
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
            "Choose Plaintext File to Encrypt",
            "",
            "All Files (*)",
        )
        if not file_path:
            return

        self.selected_file_path = file_path
        file_name = Path(file_path).name
        self.selected_file_label.setText(file_name)
        self.selected_file_label.setToolTip(file_path)
        self.encrypt_btn.setEnabled(True)
        self._set_status("Plaintext selected")

    def _common_key_or_warn(self) -> bytes | None:
        try:
            return normalize_common_key(self.key_input.text())
        except ValueError as exc:
            self._set_status("Key is too short", "error")
            QMessageBox.warning(self, "Key Too Short", str(exc))
            self.key_input.setFocus()
            return None

    def _start_encryption(self) -> None:
        if not self.selected_file_path:
            self._set_status("Choose a plaintext file", "error")
            return
        if self._worker_thread and self._worker_thread.isRunning():
            self._set_status("Operation in progress", "working")
            return

        common_key = self._common_key_or_warn()
        if common_key is None:
            return

        try:
            raw_data = Path(self.selected_file_path).read_bytes()
        except OSError as exc:
            self._set_status("Could not read plaintext", "error")
            QMessageBox.critical(self, "File Read Failed", str(exc))
            return

        algorithm = self.algorithm_box.currentText()
        input_path = Path(self.selected_file_path)
        suggested_path = input_path.with_name(
            f"{input_path.name}.{algorithm.lower()}.ttwc"
        )
        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Ciphertext File",
            str(suggested_path),
            "SDCC Files (*.ttwc)",
        )
        if not output_path:
            return
        if not output_path.lower().endswith(".ttwc"):
            output_path += ".ttwc"

        self._pending_output_path = Path(output_path)
        self._pending_plaintext = raw_data
        self._pending_package = None
        self._operation_input_name = input_path.name
        self._start_worker(
            operation="encrypt",
            data=raw_data,
            algorithm=algorithm,
            key=common_key,
        )

    def _start_decryption(self) -> None:
        if self._worker_thread and self._worker_thread.isRunning():
            self._set_status("Operation in progress", "working")
            return

        common_key = self._common_key_or_warn()
        if common_key is None:
            return

        input_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Ciphertext File",
            "",
            "SDCC Files (*.ttwc);;All Files (*)",
        )
        if not input_path:
            return

        try:
            package = parse_ciphertext_package(Path(input_path).read_bytes())
            config = ALGORITHM_CONFIGS.get(package.algorithm)
            if config is None:
                raise CiphertextFormatError(
                    f"Unsupported algorithm in ciphertext: {package.algorithm}"
                )
            block_size = config["block_size"]
            expected_size = max(
                block_size,
                ((package.original_size + block_size - 1) // block_size) * block_size,
            )
            if len(package.ciphertext) != expected_size:
                raise CiphertextFormatError(
                    "The ciphertext payload size does not match its header."
                )
        except OSError as exc:
            self._set_status("Could not read ciphertext", "error")
            QMessageBox.critical(self, "File Read Failed", str(exc))
            return
        except CiphertextFormatError as exc:
            self._set_status("Invalid ciphertext", "error")
            QMessageBox.warning(self, "Invalid Ciphertext", str(exc))
            return

        original_name = Path(package.original_name or "recovered_file")
        suggested_name = (
            f"recovered_{original_name.stem}.{package.algorithm.lower()}"
            f"{original_name.suffix}"
        )
        suggested_path = Path(input_path).with_name(suggested_name)
        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Recovered File",
            str(suggested_path),
            "All Files (*)",
        )
        if not output_path:
            return
        output_path = str(
            add_algorithm_to_recovered_path(Path(output_path), package.algorithm)
        )

        self._pending_output_path = Path(output_path)
        self._pending_plaintext = None
        self._pending_package = package
        self._operation_input_name = Path(input_path).name
        self._start_worker(
            operation="decrypt",
            data=package.ciphertext,
            algorithm=package.algorithm,
            key=common_key,
        )

    def _start_worker(
        self,
        *,
        operation: str,
        data: bytes,
        algorithm: str,
        key: bytes,
    ) -> None:
        self.progress.setValue(0)
        self._set_status(f"Running {operation}ion...", "working")
        self._set_controls_enabled(False)

        self._worker_thread = QThread(self)
        self._worker = FileOperationWorker(
            operation=operation,
            data=data,
            algorithm=algorithm,
            key=key,
            iterations=self.iterations_box.value(),
            cpu_profile=self.cpu_profile,
        )
        self._worker.moveToThread(self._worker_thread)

        self._worker_thread.started.connect(self._worker.run)
        self._worker.progress.connect(self.progress.setValue)
        self._worker.finished.connect(self._on_operation_finished)
        self._worker.failed.connect(self._on_operation_failed)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.failed.connect(self._worker_thread.quit)
        self._worker_thread.finished.connect(self._cleanup_worker_thread)
        self._worker_thread.start()

    def _on_operation_finished(
        self,
        operation: str,
        algorithm: str,
        metrics: dict[str, float | int],
        output: bytes,
    ) -> None:
        try:
            if self._pending_output_path is None:
                raise OSError("No output path was selected.")

            if operation == "encrypt":
                if self._pending_plaintext is None:
                    raise OSError("The plaintext operation context was lost.")
                file_data = build_ciphertext_package(
                    algorithm=algorithm,
                    original_name=self._operation_input_name,
                    plaintext=self._pending_plaintext,
                    ciphertext=output,
                )
                self._pending_output_path.write_bytes(file_data)
                table = self.encryption_table
                analysis_index = 0
                status = "Encryption complete"
            else:
                if self._pending_package is None:
                    raise OSError("The ciphertext operation context was lost.")
                recovered = output[: self._pending_package.original_size]
                if not self._pending_package.verify_plaintext(recovered):
                    raise CiphertextFormatError(
                        "Verification failed. The key is incorrect or the ciphertext is damaged."
                    )
                self._pending_output_path.write_bytes(recovered)
                table = self.decryption_table
                analysis_index = 1
                status = "Decryption complete"

            self._append_analysis_row(
                table=table,
                algorithm=algorithm,
                input_name=self._operation_input_name,
                metrics=metrics,
                output_path=self._pending_output_path,
            )
            self._append_history(
                operation=operation,
                file_name=self._operation_input_name,
                algorithm=algorithm,
                metrics=metrics,
                output_path=self._pending_output_path,
            )
            self.analysis_tabs.setCurrentIndex(analysis_index)
            self._set_status(status, "success")
        except CiphertextFormatError as exc:
            self._set_status("Verification failed", "error")
            QMessageBox.warning(self, "Decryption Failed", str(exc))
        except OSError as exc:
            self._set_status("Could not save output", "error")
            QMessageBox.critical(self, "File Save Failed", str(exc))
        finally:
            self._clear_pending_operation()
            self._set_controls_enabled(True)

    def _on_operation_failed(self, message: str) -> None:
        self._set_status("File operation failed", "error")
        QMessageBox.critical(self, "Operation Failed", message)
        self._clear_pending_operation()
        self._set_controls_enabled(True)

    def _set_controls_enabled(self, enabled: bool) -> None:
        self.select_file_btn.setEnabled(enabled)
        self.key_input.setEnabled(enabled)
        self.show_key_box.setEnabled(enabled)
        self.algorithm_box.setEnabled(enabled)
        self.iterations_box.setEnabled(enabled)
        self.decrypt_btn.setEnabled(enabled)
        self.encrypt_btn.setEnabled(enabled and self.selected_file_path is not None)
        if enabled:
            self.progress.setValue(0)

    def _clear_pending_operation(self) -> None:
        self._pending_output_path = None
        self._pending_plaintext = None
        self._pending_package = None
        self._operation_input_name = ""

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
        operation: str,
        file_name: str,
        algorithm: str,
        metrics: dict[str, float | int],
        output_path: Path,
    ) -> None:
        row_values = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            operation.title(),
            file_name,
            algorithm,
            str(metrics["iterations"]),
            f"{float(metrics['time_ms']):.3f}",
            f"{float(metrics['throughput_mb_s']):.3f}",
            str(metrics["memory_kb"]),
            f"{float(metrics['cpu_usage_pct']):.2f}",
            self._format_energy(float(metrics["energy_j"])),
            output_path.name,
        ]
        table_row = self.history_table.rowCount()
        self.history_table.insertRow(table_row)
        for col_idx, value in enumerate(row_values):
            item = QTableWidgetItem(value)
            if col_idx in {4, 5, 6, 7, 8, 9}:
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                )
            self.history_table.setItem(table_row, col_idx, item)
        self._history_rows.append(row_values)
        self.export_json_btn.setEnabled(True)
        self.export_csv_btn.setEnabled(True)
        self.clear_history_btn.setEnabled(True)

    def _append_analysis_row(
        self,
        *,
        table: QTableWidget,
        algorithm: str,
        input_name: str,
        metrics: dict[str, float | int],
        output_path: Path,
    ) -> None:
        row_values = [
            algorithm,
            input_name,
            str(metrics["iterations"]),
            f"{float(metrics['time_ms']):.3f}",
            f"{float(metrics['throughput_mb_s']):.3f}",
            str(metrics["memory_kb"]),
            f"{float(metrics['cpu_usage_pct']):.2f}",
            self._format_energy(float(metrics["energy_j"])),
            output_path.name,
        ]
        row_index = table.rowCount()
        table.insertRow(row_index)
        for column, value in enumerate(row_values):
            item = QTableWidgetItem(value)
            if column == 0:
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter
                )
            elif column in {2, 3, 4, 5, 6, 7}:
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                )
            if column == 8:
                item.setToolTip(str(output_path))
            table.setItem(row_index, column, item)
        operation = "encrypt" if table is self.encryption_table else "decrypt"
        self._update_graph_data(
            operation=operation,
            algorithm=algorithm,
            metrics=metrics,
        )

    def _update_graph_data(
        self,
        *,
        operation: str,
        algorithm: str,
        metrics: dict[str, float | int],
    ) -> None:
        self._graph_data[operation][algorithm] = {
            metric_key: float(metrics[metric_key])
            for metric_key, _ in GRAPH_METRICS
        }
        for metric_key, _ in GRAPH_METRICS:
            values = {
                algo: algo_metrics[metric_key]
                for algo, algo_metrics in self._graph_data[operation].items()
            }
            self._graph_charts[operation][metric_key].update_values(values)

    def _clear_history(self) -> None:
        self.history_table.setRowCount(0)
        self._history_rows.clear()
        self.encryption_table.setRowCount(0)
        self.decryption_table.setRowCount(0)
        for operation in self._graph_data:
            self._graph_data[operation].clear()
            for chart in self._graph_charts[operation].values():
                chart.update_values({})
        self.export_json_btn.setEnabled(False)
        self.export_csv_btn.setEnabled(False)
        self.clear_history_btn.setEnabled(False)
        self._set_status("History cleared")

    def _export_history_json(self) -> None:
        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis History as JSON",
            "crypto-analysis-history.json",
            "JSON Files (*.json)",
        )
        if not output_path:
            return
        if not output_path.lower().endswith(".json"):
            output_path += ".json"
        try:
            records = [dict(zip(HISTORY_HEADERS, row)) for row in self._history_rows]
            Path(output_path).write_text(
                json.dumps(records, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            self._set_status("Could not export JSON", "error")
            QMessageBox.critical(self, "Export Failed", str(exc))
            return
        self._set_status("JSON history exported", "success")

    def _export_history_csv(self) -> None:
        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis History as CSV",
            "crypto-analysis-history.csv",
            "CSV Files (*.csv)",
        )
        if not output_path:
            return
        if not output_path.lower().endswith(".csv"):
            output_path += ".csv"
        try:
            with Path(output_path).open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(HISTORY_HEADERS)
                writer.writerows(self._history_rows)
        except OSError as exc:
            self._set_status("Could not export CSV", "error")
            QMessageBox.critical(self, "Export Failed", str(exc))
            return
        self._set_status("CSV history exported", "success")

    @staticmethod
    def _format_energy(energy_joules: float) -> str:
        if energy_joules >= 1.0:
            return f"{energy_joules:.3f} J"
        if energy_joules >= 1e-3:
            return f"{energy_joules * 1e3:.3f} mJ"
        return f"{energy_joules * 1e6:.3f} uJ"

