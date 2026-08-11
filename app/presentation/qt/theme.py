APP_STYLESHEET = """
QMainWindow, QWidget#appRoot {
    background: #eef8ff;
}

QWidget {
    color: #123047;
    font-family: "Segoe UI";
    font-size: 10pt;
}

QFrame#appHeader, QFrame#controlsPanel {
    background: #ffffff;
    border: 1px solid #cfe7f7;
    border-radius: 8px;
}

QLabel#appTitle {
    color: #0b2f4a;
    font-size: 19px;
    font-weight: 700;
}

QLabel#appSubtitle, QLabel#fileValue, QLabel#sectionMeta {
    color: #557084;
}

QLabel#appSubtitle {
    font-size: 9.5pt;
}

QLabel#sectionTitle {
    color: #0f3b5f;
    font-size: 13px;
    font-weight: 650;
}

QLabel#statusBadge {
    background: #e8f5ff;
    border: 1px solid #cbe7fb;
    border-radius: 6px;
    color: #42687f;
    font-weight: 600;
    padding: 6px 10px;
}

QLabel#statusBadge[tone="success"] {
    background: #e8fbf4;
    border-color: #b6ecd8;
    color: #087457;
}

QLabel#statusBadge[tone="working"] {
    background: #fff8e6;
    border-color: #f5d78b;
    color: #92620f;
}

QLabel#statusBadge[tone="error"] {
    background: #fff0f3;
    border-color: #f5bec9;
    color: #aa2f4a;
}

QTabWidget#primaryTabs::pane, QTabWidget#analysisTabs::pane {
    background: transparent;
    border: 0;
}

QTabWidget#primaryTabs QTabBar::tab {
    background: transparent;
    border: 0;
    color: #5c7383;
    font-weight: 600;
    padding: 9px 14px;
    margin-right: 6px;
}

QTabWidget#primaryTabs QTabBar::tab:selected {
    border-bottom: 2px solid #38bdf8;
    color: #082f49;
}

QTabWidget#analysisTabs QTabBar::tab {
    background: #e3f3ff;
    border: 1px solid #cce4f5;
    border-bottom: 0;
    color: #58758a;
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
    border-bottom: 2px solid #0ea5e9;
    color: #075985;
}

QLineEdit, QComboBox, QSpinBox {
    background: #ffffff;
    border: 1px solid #bdd9eb;
    border-radius: 6px;
    min-height: 34px;
    padding: 0 10px;
    selection-background-color: #bae6fd;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 2px solid #0ea5e9;
    padding: 0 9px;
}

QComboBox::drop-down, QSpinBox::up-button, QSpinBox::down-button {
    border: 0;
    width: 24px;
}

QCheckBox {
    color: #58758a;
    spacing: 7px;
}

QPushButton {
    background: #ffffff;
    border: 1px solid #bdd9eb;
    border-radius: 6px;
    color: #173b55;
    font-weight: 600;
    min-height: 34px;
    padding: 0 14px;
}

QPushButton:hover {
    background: #f0f9ff;
    border-color: #7dd3fc;
}

QPushButton:pressed {
    background: #e0f2fe;
}

QPushButton:disabled {
    background: #e9f2f8;
    border-color: #d4e5ef;
    color: #93a8b5;
}

QPushButton#encryptButton {
    background: #0284c7;
    border-color: #0284c7;
    color: #ffffff;
}

QPushButton#encryptButton:hover {
    background: #0369a1;
    border-color: #0369a1;
}

QPushButton#decryptButton {
    background: #2563eb;
    border-color: #2563eb;
    color: #ffffff;
}

QPushButton#decryptButton:hover {
    background: #1d4ed8;
    border-color: #1d4ed8;
}

QProgressBar {
    background: #dbeefa;
    border: 0;
    border-radius: 4px;
    max-height: 8px;
    min-height: 8px;
}

QProgressBar::chunk {
    background: #38bdf8;
    border-radius: 4px;
}

QTableWidget {
    background: #ffffff;
    alternate-background-color: #f4fbff;
    border: 1px solid #cfe7f7;
    border-radius: 6px;
    gridline-color: #e1f0fa;
    selection-background-color: #d9f0ff;
    selection-color: #082f49;
}

QHeaderView::section {
    background: #e5f4ff;
    border: 0;
    border-right: 1px solid #cfe2ef;
    border-bottom: 1px solid #c5dbe9;
    color: #214d68;
    font-weight: 650;
    padding: 9px 8px;
}

QTableCornerButton::section {
    background: #e5f4ff;
    border: 0;
}

QScrollBar:vertical {
    background: transparent;
    margin: 3px;
    width: 10px;
}

QScrollBar::handle:vertical {
    background: #9fcce8;
    border-radius: 4px;
    min-height: 28px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
"""
