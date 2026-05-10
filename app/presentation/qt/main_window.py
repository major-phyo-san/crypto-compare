from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
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


class MainWindow(QMainWindow):
    """Main UI shell for crypto algorithm comparison."""

    def __init__(self) -> None:
        super().__init__()
        self.selected_file_path: str | None = None
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
        subtitle = QLabel("AES vs PRESENT vs SPECK")
        subtitle.setStyleSheet("color: #666;")

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

        self.mode_box = QComboBox()
        self.mode_box.addItems(["ECB (Prototype)", "CBC", "CTR"])

        self.run_all_btn = QPushButton("Run Compare (Mock)")
        self.run_all_btn.clicked.connect(self._populate_mock_results)
        self.run_all_btn.setEnabled(False)

        self.progress = QProgressBar()
        self.progress.setValue(0)

        controls_layout.addWidget(QLabel("Input File"), 0, 0)
        controls_layout.addWidget(self.select_file_btn, 0, 1)
        controls_layout.addWidget(self.selected_file_label, 0, 2)
        controls_layout.addWidget(QLabel("Iterations"), 1, 0)
        controls_layout.addWidget(self.iterations_box, 1, 1)
        controls_layout.addWidget(QLabel("Mode"), 2, 0)
        controls_layout.addWidget(self.mode_box, 2, 1)
        controls_layout.addWidget(self.run_all_btn, 1, 2)
        controls_layout.addWidget(self.progress, 2, 2)

        self.results_table = QTableWidget(3, 7)
        self.results_table.setHorizontalHeaderLabels(
            [
                "Algorithm",
                "Enc Time (ms)",
                "Dec Time (ms)",
                "Throughput (MB/s)",
                "Memory (KB)",
                "CPU Usage (%)",
                "Energy (W)",
            ]
        )
        self.results_table.verticalHeader().setVisible(False)

        self.summary_box = QTextEdit()
        self.summary_box.setReadOnly(True)
        self.summary_box.setPlaceholderText("Comparison insights will appear here...")

        layout.addWidget(controls_group)
        layout.addWidget(self.results_table, stretch=2)
        layout.addWidget(self.summary_box, stretch=1)
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
                "Avg Energy (W)",
                "Mode",
            ]
        )
        self.history_table.verticalHeader().setVisible(False)

        actions = QHBoxLayout()
        self.export_json_btn = QPushButton("Export JSON")
        self.export_csv_btn = QPushButton("Export CSV")
        self.clear_history_btn = QPushButton("Clear History")
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

    def _populate_mock_results(self) -> None:
        if not self.selected_file_path:
            self.status_label.setText("Choose a file before running comparison")
            return

        rows = [
            ("AES", 4.2, 4.1, 238.0, 910, 32.5, 12.8),
            ("PRESENT", 8.8, 8.5, 117.3, 604, 24.6, 9.7),
            ("SPECK", 3.4, 3.3, 280.2, 552, 37.1, 14.2),
        ]
        for row_idx, row in enumerate(rows):
            for col_idx, value in enumerate(row):
                self.results_table.setItem(row_idx, col_idx, QTableWidgetItem(str(value)))

        self.progress.setValue(100)
        self.status_label.setText("Mock comparison complete")
        self.summary_box.setPlainText(
            f"File: {Path(self.selected_file_path).name}\n"
            "SPECK shows highest throughput in this mock dataset but with higher CPU and power draw."
        )


