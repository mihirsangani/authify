"""
Master password unlock / setup dialog.
"""

from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)


class UnlockDialog(QDialog):
    """Prompt the user to enter (or create) their master password."""

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        is_new: bool = False,
    ) -> None:
        super().__init__(parent)
        self._is_new = is_new
        self.password: Optional[str] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        if self._is_new:
            self.setWindowTitle("Create Master Password")
        else:
            self.setWindowTitle("Unlock Authify")

        self.setMinimumWidth(380)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(28, 28, 28, 28)

        title_lbl = QLabel(
            "Create Master Password" if self._is_new else "Unlock Authify"
        )
        title_lbl.setObjectName("lbl_title")
        layout.addWidget(title_lbl)

        if self._is_new:
            info = QLabel(
                "Choose a strong master password.\n"
                "This encrypts your TOTP secrets — it CANNOT be recovered."
            )
        else:
            info = QLabel("Enter your master password to unlock the vault.")
        info.setWordWrap(True)
        info.setObjectName("lbl_issuer")
        layout.addWidget(info)

        self._edit_pw = QLineEdit()
        self._edit_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._edit_pw.setPlaceholderText("Master password")
        self._edit_pw.returnPressed.connect(self._on_accept)
        layout.addWidget(self._edit_pw)

        if self._is_new:
            self._edit_confirm = QLineEdit()
            self._edit_confirm.setEchoMode(QLineEdit.EchoMode.Password)
            self._edit_confirm.setPlaceholderText("Confirm master password")
            self._edit_confirm.returnPressed.connect(self._on_accept)
            layout.addWidget(self._edit_confirm)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.button(QDialogButtonBox.StandardButton.Ok).setObjectName("btn_primary")
        btn_box.button(QDialogButtonBox.StandardButton.Ok).setText(
            "Create" if self._is_new else "Unlock"
        )
        btn_box.accepted.connect(self._on_accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _on_accept(self) -> None:
        pw = self._edit_pw.text()
        if len(pw) < 8:
            QMessageBox.warning(
                self, "Too Short", "Password must be at least 8 characters."
            )
            return
        if self._is_new:
            confirm = self._edit_confirm.text()
            if pw != confirm:
                QMessageBox.warning(
                    self, "Mismatch", "Passwords do not match."
                )
                self._edit_confirm.clear()
                return
        self.password = pw
        self.accept()
