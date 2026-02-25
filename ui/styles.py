"""
Qt stylesheets and theme helpers for Authify.
"""

DARK_STYLESHEET = """
/* ── Global ──────────────────────────────────────────────────────── */
QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: "Segoe UI", "SF Pro Display", "Ubuntu", sans-serif;
    font-size: 14px;
}

QMainWindow, QDialog {
    background-color: #1e1e2e;
}

/* ── Buttons ─────────────────────────────────────────────────────── */
QPushButton {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #45475a;
    border-color: #7f849c;
}
QPushButton:pressed {
    background-color: #585b70;
}
QPushButton#btn_primary {
    background-color: #89b4fa;
    color: #1e1e2e;
    border: none;
    font-weight: 700;
}
QPushButton#btn_primary:hover {
    background-color: #b4befe;
}
QPushButton#btn_danger {
    background-color: #f38ba8;
    color: #1e1e2e;
    border: none;
    font-weight: 700;
}
QPushButton#btn_danger:hover {
    background-color: #eba0ac;
}
QPushButton#btn_icon {
    background: transparent;
    border: none;
    padding: 4px;
    border-radius: 6px;
}
QPushButton#btn_icon:hover {
    background-color: #313244;
}

/* ── Input fields ────────────────────────────────────────────────── */
QLineEdit, QComboBox, QSpinBox {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 8px 12px;
    selection-background-color: #89b4fa;
    selection-color: #1e1e2e;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border-color: #89b4fa;
}
QLineEdit:disabled {
    color: #6c7086;
    background-color: #252535;
}

/* ── ComboBox drop-down ──────────────────────────────────────────── */
QComboBox::drop-down {
    border: none;
    width: 28px;
}
QComboBox QAbstractItemView {
    background-color: #313244;
    border: 1px solid #45475a;
    selection-background-color: #89b4fa;
    selection-color: #1e1e2e;
    border-radius: 6px;
}

/* ── Labels ──────────────────────────────────────────────────────── */
QLabel#lbl_code {
    font-size: 40px;
    font-weight: 700;
    letter-spacing: 6px;
    color: #cba6f7;
    qproperty-alignment: AlignCenter;
}
QLabel#lbl_account_name {
    font-size: 15px;
    font-weight: 600;
    color: #89b4fa;
}
QLabel#lbl_issuer {
    font-size: 12px;
    color: #7f849c;
}
QLabel#lbl_title {
    font-size: 22px;
    font-weight: 700;
    color: #cba6f7;
}
QLabel#lbl_form {
    font-size: 12px;
    font-weight: 600;
    color: #7f849c;
    text-transform: uppercase;
    letter-spacing: 1px;
}
QLabel#lbl_remaining {
    font-size: 12px;
    color: #a6e3a1;
}

/* ── Scroll bar ──────────────────────────────────────────────────── */
QScrollArea, QScrollBar {
    background: transparent;
}
QScrollBar:vertical {
    width: 6px;
    background: transparent;
}
QScrollBar::handle:vertical {
    background: #45475a;
    border-radius: 3px;
    min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

/* ── List / Cards ────────────────────────────────────────────────── */
QFrame#card {
    background-color: #24273a;
    border: 1px solid #313244;
    border-radius: 12px;
}
QFrame#card:hover {
    border-color: #585b70;
}

/* ── Separators ──────────────────────────────────────────────────── */
QFrame[frameShape="4"], QFrame[frameShape="5"] {
    color: #313244;
}

/* ── Tooltips ────────────────────────────────────────────────────── */
QToolTip {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 6px 10px;
}

/* ── Progress bar ────────────────────────────────────────────────── */
QProgressBar {
    background-color: #313244;
    border: none;
    border-radius: 4px;
    height: 6px;
    text-visible: false;
}
QProgressBar::chunk {
    background-color: #a6e3a1;
    border-radius: 4px;
}
QProgressBar[low="true"]::chunk {
    background-color: #f38ba8;
}

/* ── Message Box ─────────────────────────────────────────────────── */
QMessageBox {
    background-color: #1e1e2e;
}

/* ── Tab widget ──────────────────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid #313244;
    border-radius: 8px;
}
QTabBar::tab {
    background: #313244;
    color: #7f849c;
    padding: 8px 20px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}
QTabBar::tab:selected {
    background: #45475a;
    color: #cdd6f4;
}
"""


LIGHT_STYLESHEET = """
QWidget {
    background-color: #eff1f5;
    color: #4c4f69;
    font-family: "Segoe UI", "SF Pro Display", "Ubuntu", sans-serif;
    font-size: 14px;
}
QPushButton {
    background-color: #dce0e8;
    color: #4c4f69;
    border: 1px solid #bcc0cc;
    border-radius: 8px;
    padding: 8px 16px;
}
QPushButton:hover { background-color: #bcc0cc; }
QPushButton#btn_primary { background-color: #1e66f5; color: #eff1f5; border: none; font-weight: 700; }
QPushButton#btn_primary:hover { background-color: #04a5e5; }
QPushButton#btn_danger { background-color: #d20f39; color: #eff1f5; border: none; font-weight: 700; }
QLineEdit, QComboBox, QSpinBox {
    background-color: #dce0e8;
    color: #4c4f69;
    border: 1px solid #bcc0cc;
    border-radius: 8px;
    padding: 8px 12px;
}
QLineEdit:focus, QComboBox:focus { border-color: #1e66f5; }
QLabel#lbl_code { font-size: 40px; font-weight: 700; letter-spacing: 6px; color: #8839ef; }
QLabel#lbl_account_name { font-size: 15px; font-weight: 600; color: #1e66f5; }
QLabel#lbl_issuer { font-size: 12px; color: #9ca0b0; }
QFrame#card { background-color: #e6e9ef; border: 1px solid #bcc0cc; border-radius: 12px; }
QProgressBar { background-color: #bcc0cc; border: none; border-radius: 4px; height: 6px; }
QProgressBar::chunk { background-color: #40a02b; border-radius: 4px; }
"""
