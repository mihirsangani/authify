"""
Authify – entry point.

Usage
-----
    python main.py

Or, if installed as a package:
    authify
"""

import logging
import sys

from PyQt6.QtWidgets import QApplication, QMessageBox

from core.crypto import derive_key, generate_salt
from storage.database import AccountDatabase
from storage.encryption import FieldEncryptor
from ui.main_window import MainWindow
from ui.styles import DARK_STYLESHEET
from ui.unlock_dialog import UnlockDialog

# ── Logging setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("authify")

# Suppress secret values from logs at WARNING+ level
logging.getLogger("core.crypto").setLevel(logging.WARNING)
logging.getLogger("storage.encryption").setLevel(logging.WARNING)


# ── Bootstrap ─────────────────────────────────────────────────────────────────

def _build_encryptor(db: AccountDatabase, password: str) -> FieldEncryptor:
    """Derive or create the master key for the database."""
    salt = db.get_salt()
    if salt is None:
        # First run – generate and store a new salt
        salt = generate_salt()
        db.set_salt(salt)
    key = derive_key(password, salt)
    return FieldEncryptor(key)


def _unlock(db: AccountDatabase, app: QApplication) -> bool:
    """
    Show the unlock / set-up dialog and attach the encryptor to ``db``.

    Returns True on success, False if the user cancelled.
    """
    is_new = not db.has_master_password()

    for attempt in range(5):
        dlg = UnlockDialog(is_new=is_new)
        if dlg.exec() != dlg.DialogCode.Accepted or dlg.password is None:
            return False

        encryptor = _build_encryptor(db, dlg.password)

        if is_new:
            # First run – accept any password (just set up the encryptor)
            db.set_encryptor(encryptor)
            logger.info("Vault initialised with new master password.")
            return True
        else:
            # Existing vault – verify by attempting to decrypt one record
            try:
                db.set_encryptor(encryptor)
                db.list_accounts()   # will raise InvalidTag on wrong password
                logger.info("Vault unlocked.")
                return True
            except Exception:
                db.set_encryptor(None)  # type: ignore[arg-type]
                remaining = 4 - attempt
                if remaining > 0:
                    QMessageBox.warning(
                        None,
                        "Wrong Password",
                        f"Incorrect master password.\n{remaining} attempt(s) remaining.",
                    )
                else:
                    QMessageBox.critical(
                        None,
                        "Too Many Attempts",
                        "Too many failed attempts. Authify will exit.",
                    )
                    return False
    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Authify")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Authify")
    app.setStyleSheet(DARK_STYLESHEET)  # pre-apply before any dialog opens

    db = AccountDatabase()

    if not _unlock(db, app):
        logger.info("Unlock cancelled or failed – exiting.")
        sys.exit(0)

    window = MainWindow(db)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
