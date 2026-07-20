APP_STYLESHEET = """
QMainWindow, QWidget#appRoot {
    background: #f3f7f5;
}

QWidget {
    color: #19312d;
    font-family: "Segoe UI";
    font-size: 10pt;
}

QFrame#appHeader, QFrame#controlsPanel {
    background: #ffffff;
    border: 1px solid #dbe6e2;
    border-radius: 8px;
}

QLabel#appTitle {
    color: #102a25;
    font-size: 19px;
    font-weight: 700;
}

QLabel#appSubtitle, QLabel#fileValue, QLabel#sectionMeta {
    color: #4f655e;
}

QLabel#appSubtitle {
    font-size: 9.5pt;
}

QLabel#sectionTitle {
    color: #173d35;
    font-size: 13px;
    font-weight: 650;
}

QLabel#statusBadge {
    background: #edf4f1;
    border: 1px solid #d7e5e0;
    border-radius: 6px;
    color: #557068;
    font-weight: 600;
    padding: 6px 10px;
}

QLabel#statusBadge[tone="success"] {
    background: #e9f7f1;
    border-color: #bfe4d5;
    color: #176b53;
}

QLabel#statusBadge[tone="working"] {
    background: #fff4e8;
    border-color: #f4d4b3;
    color: #99521e;
}

QLabel#statusBadge[tone="error"] {
    background: #fff0ef;
    border-color: #f1c5c1;
    color: #a23c34;
}

QTabWidget#primaryTabs::pane, QTabWidget#analysisTabs::pane {
    background: transparent;
    border: 0;
}

QTabWidget#primaryTabs QTabBar::tab {
    background: transparent;
    border: 0;
    color: #667a74;
    font-weight: 600;
    padding: 9px 14px;
    margin-right: 6px;
}

QTabWidget#primaryTabs QTabBar::tab:selected {
    border-bottom: 2px solid #e46f51;
    color: #163e35;
}

QTabWidget#analysisTabs QTabBar::tab {
    background: #eaf1ee;
    border: 1px solid #d9e5e0;
    border-bottom: 0;
    color: #587069;
    font-weight: 600;
    padding: 8px 14px;
    margin-right: 4px;
}

QTabWidget#analysisTabs QTabBar::tab:first {
    border-top-left-radius: 6px;
}

QTabWidget#analysisTabs QTabBar::tab:last {
    border-top-right-radius: 6px;
}

QTabWidget#analysisTabs QTabBar::tab:selected {
    background: #ffffff;
    border-bottom: 2px solid #1b8a74;
    color: #116b5c;
}

QLineEdit, QComboBox, QSpinBox {
    background: #ffffff;
    border: 1px solid #cbdad5;
    border-radius: 6px;
    min-height: 34px;
    padding: 0 10px;
    selection-background-color: #bde5da;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 2px solid #1b8a74;
    padding: 0 9px;
}

QComboBox::drop-down, QSpinBox::up-button, QSpinBox::down-button {
    border: 0;
    width: 24px;
}

QCheckBox {
    color: #587069;
    spacing: 7px;
}

QPushButton {
    background: #ffffff;
    border: 1px solid #c8d7d2;
    border-radius: 6px;
    color: #24463e;
    font-weight: 600;
    min-height: 34px;
    padding: 0 14px;
}

QPushButton:hover {
    background: #f5faf8;
    border-color: #8fb6aa;
}

QPushButton:pressed {
    background: #e8f2ee;
}

QPushButton:disabled {
    background: #edf2f0;
    border-color: #dce5e2;
    color: #9aa9a4;
}

QPushButton#encryptButton {
    background: #127765;
    border-color: #127765;
    color: #ffffff;
}

QPushButton#encryptButton:hover {
    background: #0e6758;
    border-color: #0e6758;
}

QPushButton#decryptButton {
    background: #29465b;
    border-color: #29465b;
    color: #ffffff;
}

QPushButton#decryptButton:hover {
    background: #203b4e;
    border-color: #203b4e;
}

QProgressBar {
    background: #dfe9e5;
    border: 0;
    border-radius: 4px;
    max-height: 8px;
    min-height: 8px;
}

QProgressBar::chunk {
    background: #27a487;
    border-radius: 4px;
}

QTableWidget {
    background: #ffffff;
    alternate-background-color: #f6faf8;
    border: 1px solid #dbe6e2;
    border-radius: 6px;
    gridline-color: #e5ece9;
    selection-background-color: #d9eee7;
    selection-color: #163e35;
}

QHeaderView::section {
    background: #eaf2ef;
    border: 0;
    border-right: 1px solid #d8e4df;
    border-bottom: 1px solid #cfddd8;
    color: #38574f;
    font-weight: 650;
    padding: 9px 8px;
}

QTableCornerButton::section {
    background: #eaf2ef;
    border: 0;
}

QScrollBar:vertical {
    background: transparent;
    margin: 3px;
    width: 10px;
}

QScrollBar::handle:vertical {
    background: #b7c9c3;
    border-radius: 4px;
    min-height: 28px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
"""
