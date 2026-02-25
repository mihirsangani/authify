"""
Main application window for Authify.

Layout
------
┌──────────────────────────────────────────────────┐
│  🔐 Authify          [+ Add]  [☀/🌙]  [⋯ Menu] │
├──────────────────────────────────────────────────┤
│  🔍 Search accounts…                             │
├──────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────┐  │
│  │  Issuer                         [copy] [⋮] │  │
│  │  Account Name                             │  │
│  │  1 2 3   4 5 6            ▓▓▓▓░░░  28 s  │  │
│  └────────────────────────────────────────────┘  │
│  … more accounts …                               │
└──────────────────────────────────────────────────┘
"""

import logging
import threading
import time
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QThread
from PyQt6.QtGui import QClipboard, QFont, QAction
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core.crypto import derive_key, generate_salt
from core.totp import generate_totp, remaining_seconds
from core.utils import decode_secret, format_otp
from storage.database import Account, AccountDatabase
from storage.encryption import FieldEncryptor
from ui.styles import DARK_STYLESHEET, LIGHT_STYLESHEET

logger = logging.getLogger(__name__)

_CLIPBOARD_CLEAR_DELAY_MS = 15_000  # 15 seconds
_AUTO_LOCK_DEFAULT_S = 300          # 5 minutes


# ── Account card widget ───────────────────────────────────────────────────────

class AccountCard(QFrame):
    """A card that displays one account's OTP code and countdown."""

    copy_requested = pyqtSignal(str)   # emits the OTP code
    edit_requested = pyqtSignal(object)   # emits Account
    delete_requested = pyqtSignal(int)    # emits account id

    def __init__(self, account: Account, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.account = account
        self._clipboard_timer: Optional[QTimer] = None
        self.setObjectName("card")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._build_ui()
        self.refresh()

    # ── Construction ──────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(4)

        # Row 1: issuer + actions
        top_row = QHBoxLayout()
        top_row.setSpacing(4)

        self._lbl_issuer = QLabel(self.account.issuer or "—")
        self._lbl_issuer.setObjectName("lbl_issuer")
        top_row.addWidget(self._lbl_issuer)

        top_row.addStretch()

        self._btn_copy = QPushButton("Copy")
        self._btn_copy.setObjectName("btn_primary")
        self._btn_copy.setFixedWidth(60)
        self._btn_copy.setToolTip("Copy OTP code to clipboard")
        self._btn_copy.clicked.connect(self._on_copy)
        top_row.addWidget(self._btn_copy)

        menu_btn = QPushButton("⋮")
        menu_btn.setObjectName("btn_icon")
        menu_btn.setFixedSize(32, 32)
        menu_btn.setToolTip("Account options")
        menu_btn.clicked.connect(self._show_menu)
        top_row.addWidget(menu_btn)

        root.addLayout(top_row)

        # Row 2: account name
        self._lbl_name = QLabel(self.account.name)
        self._lbl_name.setObjectName("lbl_account_name")
        root.addWidget(self._lbl_name)

        # Row 3: code + countdown
        code_row = QHBoxLayout()
        code_row.setSpacing(12)

        self._lbl_code = QLabel("— — —")
        self._lbl_code.setObjectName("lbl_code")
        self._lbl_code.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        code_row.addWidget(self._lbl_code)

        code_row.addStretch()

        right_col = QVBoxLayout()
        right_col.setSpacing(2)
        self._progress = QProgressBar()
        self._progress.setFixedWidth(100)
        self._progress.setTextVisible(False)
        right_col.addWidget(self._progress)

        self._lbl_remaining = QLabel("")
        self._lbl_remaining.setObjectName("lbl_remaining")
        self._lbl_remaining.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_col.addWidget(self._lbl_remaining)

        code_row.addLayout(right_col)
        root.addLayout(code_row)

    # ── Public API ────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Regenerate the OTP and update all visual elements."""
        try:
            secret_bytes = decode_secret(self.account.secret)
            if self.account.otp_type == "totp":
                code = generate_totp(
                    secret_bytes,
                    digits=self.account.digits,
                    period=self.account.period,
                    algorithm=self.account.algorithm,
                )
                rem = remaining_seconds(self.account.period)
                total = self.account.period

                self._lbl_code.setText(format_otp(code))
                self._progress.setMaximum(total)
                self._progress.setValue(rem)

                # Turn red when ≤5 s remaining
                low = rem <= 5
                self._progress.setProperty("low", str(low).lower())
                self._progress.style().unpolish(self._progress)
                self._progress.style().polish(self._progress)

                self._lbl_remaining.setText(f"{rem}s")
            else:
                # HOTP — static display
                from core.hotp import generate_hotp
                code = generate_hotp(
                    secret_bytes,
                    self.account.counter,
                    self.account.digits,
                    self.account.algorithm,
                )
                self._lbl_code.setText(format_otp(code))
                self._progress.setMaximum(1)
                self._progress.setValue(1)
                self._lbl_remaining.setText("HOTP")

        except Exception:
            logger.exception("Failed to generate OTP for %s", self.account.name)
            self._lbl_code.setText("ERROR")

    def update_account(self, account: Account) -> None:
        self.account = account
        self._lbl_issuer.setText(account.issuer or "—")
        self._lbl_name.setText(account.name)
        self.refresh()

    # ── Slots ─────────────────────────────────────────────────────────

    def _on_copy(self) -> None:
        try:
            secret_bytes = decode_secret(self.account.secret)
            code = generate_totp(
                secret_bytes,
                digits=self.account.digits,
                period=self.account.period,
                algorithm=self.account.algorithm,
            ) if self.account.otp_type == "totp" else self._lbl_code.text().replace(" ", "")
        except Exception:
            return

        self.copy_requested.emit(code)

    def _show_menu(self) -> None:
        menu = QMenu(self)
        edit_action = QAction("Edit", self)
        edit_action.triggered.connect(lambda: self.edit_requested.emit(self.account))
        menu.addAction(edit_action)

        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(lambda: self.delete_requested.emit(self.account.id))
        menu.addAction(delete_action)

        menu.exec(self.mapToGlobal(self.rect().center()))


# ── Main window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """Authify main window."""

    def __init__(self, db: AccountDatabase) -> None:
        super().__init__()
        self._db = db
        self._cards: Dict[int, AccountCard] = {}
        self._dark_mode = True
        self._auto_lock_timer: Optional[QTimer] = None
        self._clipboard_clear_timer: Optional[QTimer] = None

        self._setup_ui()
        self._apply_theme()
        self._load_accounts()
        self._start_refresh_timer()
        self._reset_auto_lock()

    # ── UI construction ───────────────────────────────────────────────

    def _setup_ui(self) -> None:
        self.setWindowTitle("Authify")
        self.setMinimumSize(480, 600)
        self.resize(520, 700)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ────────────────────────────────────────────────────
        header = QWidget()
        header.setObjectName("header")
        header.setStyleSheet(
            "QWidget#header { background-color: #181825; "
            "border-bottom: 1px solid #313244; }"
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 14, 20, 14)
        header_layout.setSpacing(10)

        title = QLabel("🔐 Authify")
        title.setObjectName("lbl_title")
        header_layout.addWidget(title)

        header_layout.addStretch()

        self._btn_import = QPushButton("Import")
        self._btn_import.setToolTip("Import encrypted backup")
        self._btn_import.clicked.connect(self._on_import)
        header_layout.addWidget(self._btn_import)

        self._btn_export = QPushButton("Export")
        self._btn_export.setToolTip("Export encrypted backup")
        self._btn_export.clicked.connect(self._on_export)
        header_layout.addWidget(self._btn_export)

        self._btn_theme = QPushButton("☀")
        self._btn_theme.setObjectName("btn_icon")
        self._btn_theme.setFixedSize(34, 34)
        self._btn_theme.setToolTip("Toggle light/dark mode")
        self._btn_theme.clicked.connect(self._toggle_theme)
        header_layout.addWidget(self._btn_theme)

        self._btn_add = QPushButton("+ Add")
        self._btn_add.setObjectName("btn_primary")
        self._btn_add.setToolTip("Add a new account")
        self._btn_add.clicked.connect(self._on_add_account)
        header_layout.addWidget(self._btn_add)

        root.addWidget(header)

        # ── Search bar ────────────────────────────────────────────────
        search_wrap = QWidget()
        search_wrap.setStyleSheet("background-color: #181825;")
        search_layout = QHBoxLayout(search_wrap)
        search_layout.setContentsMargins(20, 8, 20, 8)

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Search accounts…")
        self._search.textChanged.connect(self._filter_cards)
        search_layout.addWidget(self._search)

        root.addWidget(search_wrap)

        # ── Scroll area for cards ─────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self._cards_widget = QWidget()
        self._cards_layout = QVBoxLayout(self._cards_widget)
        self._cards_layout.setContentsMargins(16, 16, 16, 16)
        self._cards_layout.setSpacing(10)
        self._cards_layout.addStretch()

        scroll.setWidget(self._cards_widget)
        root.addWidget(scroll)

        # ── Status bar ────────────────────────────────────────────────
        self._status = self.statusBar()
        self._status.showMessage("Ready")

    # ── Theme ─────────────────────────────────────────────────────────

    def _apply_theme(self) -> None:
        sheet = DARK_STYLESHEET if self._dark_mode else LIGHT_STYLESHEET
        QApplication.instance().setStyleSheet(sheet)  # type: ignore[union-attr]
        self._btn_theme.setText("☀" if self._dark_mode else "🌙")

    def _toggle_theme(self) -> None:
        self._dark_mode = not self._dark_mode
        self._apply_theme()

    # ── Account loading ───────────────────────────────────────────────

    def _load_accounts(self) -> None:
        """Fetch accounts from DB and populate the card list."""
        # Remove existing cards (before the stretch)
        for card in list(self._cards.values()):
            self._cards_layout.removeWidget(card)
            card.deleteLater()
        self._cards.clear()

        try:
            accounts = self._db.list_accounts()
        except Exception:
            logger.exception("Failed to load accounts")
            return

        for account in accounts:
            self._add_card(account)

        self._update_empty_state()

    def _add_card(self, account: Account) -> None:
        card = AccountCard(account)
        card.copy_requested.connect(self._copy_to_clipboard)
        card.edit_requested.connect(self._on_edit_account)
        card.delete_requested.connect(self._on_delete_account)
        # Insert before the stretch (last item)
        pos = self._cards_layout.count() - 1
        self._cards_layout.insertWidget(pos, card)
        self._cards[account.id] = card  # type: ignore[index]

    def _update_empty_state(self) -> None:
        if not self._cards:
            if not hasattr(self, "_empty_lbl"):
                self._empty_lbl = QLabel(
                    "No accounts yet.\nClick  + Add  to get started."
                )
                self._empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                self._empty_lbl.setObjectName("lbl_issuer")
                self._empty_lbl.setWordWrap(True)
                # Insert before stretch
                self._cards_layout.insertWidget(0, self._empty_lbl)
        else:
            if hasattr(self, "_empty_lbl") and self._empty_lbl.parent():
                self._cards_layout.removeWidget(self._empty_lbl)
                self._empty_lbl.hide()

    # ── Refresh timer ─────────────────────────────────────────────────

    def _start_refresh_timer(self) -> None:
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_all_cards)
        self._refresh_timer.start(1000)

    def _refresh_all_cards(self) -> None:
        for card in self._cards.values():
            if not card.isHidden():
                card.refresh()

    # ── Auto-lock ─────────────────────────────────────────────────────

    def _reset_auto_lock(self) -> None:
        if self._auto_lock_timer:
            self._auto_lock_timer.stop()
        self._auto_lock_timer = QTimer(self)
        self._auto_lock_timer.setSingleShot(True)
        self._auto_lock_timer.timeout.connect(self._lock_vault)
        self._auto_lock_timer.start(_AUTO_LOCK_DEFAULT_S * 1000)

    def _lock_vault(self) -> None:
        self._db.set_encryptor(None)  # type: ignore[arg-type]
        for card in self._cards.values():
            card.hide()
        QMessageBox.information(
            self,
            "Vault Locked",
            "Authify has been locked due to inactivity.\nRestart to unlock.",
        )
        self.close()

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        self._reset_auto_lock()
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:  # type: ignore[override]
        self._reset_auto_lock()
        super().keyPressEvent(event)

    # ── Search / filter ───────────────────────────────────────────────

    def _filter_cards(self, text: str) -> None:
        lower = text.strip().lower()
        for account_id, card in self._cards.items():
            visible = (
                lower in card.account.name.lower()
                or lower in card.account.issuer.lower()
            )
            card.setVisible(visible or not lower)

    # ── Account CRUD ──────────────────────────────────────────────────

    def _on_add_account(self) -> None:
        from ui.add_account import AddAccountDialog
        from qr.scanner import QRScanner

        qr_ok = QRScanner(on_result=lambda _: None).is_available
        dlg = AddAccountDialog(self, qr_available=qr_ok)
        dlg.account_saved.connect(self._save_new_account)
        dlg.exec()

    def _save_new_account(self, account: Account) -> None:
        try:
            new_id = self._db.add_account(account)
            account.id = new_id
            self._add_card(account)
            self._update_empty_state()
            self._status.showMessage(f"Account '{account.name}' added.", 3000)
        except Exception as exc:
            logger.exception("Failed to add account")
            QMessageBox.critical(self, "Error", f"Failed to add account:\n{exc}")

    def _on_edit_account(self, account: Account) -> None:
        from ui.add_account import AddAccountDialog
        from qr.scanner import QRScanner

        qr_ok = QRScanner(on_result=lambda _: None).is_available
        dlg = AddAccountDialog(self, account=account, qr_available=qr_ok)
        dlg.account_saved.connect(self._save_edited_account)
        dlg.exec()

    def _save_edited_account(self, account: Account) -> None:
        try:
            self._db.update_account(account)
            if account.id in self._cards:
                self._cards[account.id].update_account(account)
            self._status.showMessage(f"Account '{account.name}' updated.", 3000)
        except Exception as exc:
            logger.exception("Failed to update account")
            QMessageBox.critical(self, "Error", f"Failed to update account:\n{exc}")

    def _on_delete_account(self, account_id: int) -> None:
        card = self._cards.get(account_id)
        name = card.account.name if card else str(account_id)

        reply = QMessageBox.question(
            self,
            "Delete Account",
            f"Permanently delete '{name}'?\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            self._db.delete_account(account_id)
            if card:
                self._cards_layout.removeWidget(card)
                card.deleteLater()
                del self._cards[account_id]
            self._update_empty_state()
            self._status.showMessage(f"Account '{name}' deleted.", 3000)
        except Exception as exc:
            logger.exception("Failed to delete account")
            QMessageBox.critical(self, "Error", f"Failed to delete:\n{exc}")

    # ── Clipboard ─────────────────────────────────────────────────────

    def _copy_to_clipboard(self, code: str) -> None:
        clipboard = QApplication.clipboard()
        clipboard.setText(code)
        self._status.showMessage("Code copied! Clearing in 15 s…", _CLIPBOARD_CLEAR_DELAY_MS)

        if self._clipboard_clear_timer:
            self._clipboard_clear_timer.stop()
        self._clipboard_clear_timer = QTimer(self)
        self._clipboard_clear_timer.setSingleShot(True)
        self._clipboard_clear_timer.timeout.connect(
            lambda: clipboard.setText("")
        )
        self._clipboard_clear_timer.start(_CLIPBOARD_CLEAR_DELAY_MS)

    # ── Export / Import ───────────────────────────────────────────────

    def _on_export(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        from core.crypto import encrypt_with_password

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Backup", "authify_backup.json",
            "JSON Files (*.json)"
        )
        if not path:
            return

        pw, ok = self._ask_password("Export", "Enter password to encrypt backup:")
        if not ok or not pw:
            return

        try:
            json_data = self._db.export_json()
            encrypted = encrypt_with_password(json_data.encode("utf-8"), pw)
            with open(path, "wb") as f:
                f.write(encrypted)
            QMessageBox.information(self, "Exported", f"Backup saved to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    def _on_import(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        from core.crypto import decrypt_with_password
        from cryptography.exceptions import InvalidTag

        path, _ = QFileDialog.getOpenFileName(
            self, "Import Backup", "", "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return

        pw, ok = self._ask_password("Import", "Enter the backup password:")
        if not ok or not pw:
            return

        try:
            with open(path, "rb") as f:
                blob = f.read()
            json_data = decrypt_with_password(blob, pw).decode("utf-8")
            count = self._db.import_json(json_data)
            self._load_accounts()
            QMessageBox.information(self, "Imported", f"Imported {count} account(s).")
        except InvalidTag:
            QMessageBox.critical(self, "Wrong Password", "Incorrect password or corrupted backup.")
        except Exception as exc:
            QMessageBox.critical(self, "Import Error", str(exc))

    def _ask_password(self, title: str, prompt: str) -> tuple[str, bool]:
        from PyQt6.QtWidgets import QInputDialog
        pw, ok = QInputDialog.getText(
            self, title, prompt,
            QLineEdit.EchoMode.Password,
        )
        return pw, ok

    # ── Cleanup ───────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._auto_lock_timer:
            self._auto_lock_timer.stop()
        self._refresh_timer.stop()
        self._db.close()
        super().closeEvent(event)
