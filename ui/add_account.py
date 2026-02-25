"""
Add / Edit account dialog for Authify.
"""

import base64
import logging
import secrets
from typing import Optional
from urllib.parse import quote

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QIcon, QImage, QPixmap
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.totp import Algorithm
from core.utils import decode_secret, normalize_secret, sanitise_label, validate_digits, validate_period
from qr.parser import parse_otpauth_uri
from storage.database import Account

logger = logging.getLogger(__name__)


class AddAccountDialog(QDialog):
    """
    Dialog for adding or editing a TOTP/HOTP account.

    Emits :attr:`account_saved` with the resulting :class:`Account` on accept.
    """

    account_saved = pyqtSignal(object)  # Account

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        account: Optional[Account] = None,
        qr_available: bool = False,
    ) -> None:
        super().__init__(parent)
        self._existing = account
        self._qr_available = qr_available
        self._setup_ui()
        if account:
            self._populate(account)
        else:
            self._auto_generate_secret()
        self._refresh_qr()

    # ── UI construction ───────────────────────────────────────────────

    def _setup_ui(self) -> None:
        title = "Edit Account" if self._existing else "Add Account"
        self.setWindowTitle(title)
        self.setMinimumWidth(460)
        self.setModal(True)

        root = QVBoxLayout(self)
        root.setSpacing(16)
        root.setContentsMargins(24, 24, 24, 24)

        # Title
        lbl_title = QLabel(title)
        lbl_title.setObjectName("lbl_title")
        root.addWidget(lbl_title)

        # Tabs
        self._tabs = QTabWidget()
        root.addWidget(self._tabs)

        # ── Tab 1: Manual entry ───────────────────────────────────────
        manual_tab = QWidget()
        form = QFormLayout(manual_tab)
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._edit_name = QLineEdit()
        self._edit_name.setPlaceholderText("e.g. user@example.com")
        form.addRow(self._make_label("Account Name *"), self._edit_name)

        self._edit_issuer = QLineEdit()
        self._edit_issuer.setPlaceholderText("e.g. GitHub")
        form.addRow(self._make_label("Issuer"), self._edit_issuer)

        self._edit_secret = QLineEdit()
        self._edit_secret.setPlaceholderText("Base32 secret key")
        self._edit_secret.setEchoMode(QLineEdit.EchoMode.Password)
        secret_row = QHBoxLayout()
        secret_row.addWidget(self._edit_secret)
        self._btn_toggle_secret = QPushButton("Show")
        self._btn_toggle_secret.setFixedWidth(60)
        self._btn_toggle_secret.setCheckable(True)
        self._btn_toggle_secret.toggled.connect(self._toggle_secret_visibility)
        secret_row.addWidget(self._btn_toggle_secret)
        self._btn_gen_secret = QPushButton("⟳")
        self._btn_gen_secret.setFixedWidth(32)
        self._btn_gen_secret.setToolTip("Generate a new random secret")
        self._btn_gen_secret.clicked.connect(self._auto_generate_secret)
        self._btn_gen_secret.clicked.connect(self._refresh_qr)
        secret_row.addWidget(self._btn_gen_secret)
        form.addRow(self._make_label("Secret *"), secret_row)

        self._combo_algorithm = QComboBox()
        for alg in Algorithm:
            self._combo_algorithm.addItem(alg.value, alg)
        form.addRow(self._make_label("Algorithm"), self._combo_algorithm)

        self._spin_digits = QSpinBox()
        self._spin_digits.setRange(6, 8)
        self._spin_digits.setSingleStep(2)
        self._spin_digits.setValue(6)
        form.addRow(self._make_label("Digits"), self._spin_digits)

        self._combo_type = QComboBox()
        self._combo_type.addItem("TOTP (time-based)", "totp")
        self._combo_type.addItem("HOTP (counter-based)", "hotp")
        self._combo_type.currentIndexChanged.connect(self._on_type_changed)
        form.addRow(self._make_label("Type"), self._combo_type)

        self._spin_period = QSpinBox()
        self._spin_period.setRange(1, 300)
        self._spin_period.setValue(30)
        self._spin_period.setSuffix(" s")
        form.addRow(self._make_label("Period"), self._spin_period)

        self._spin_counter = QSpinBox()
        self._spin_counter.setRange(0, 2_147_483_647)
        self._spin_counter.setValue(0)
        self._spin_counter.setVisible(False)
        self._lbl_counter = self._make_label("Initial Counter")
        self._lbl_counter.setVisible(False)
        form.addRow(self._lbl_counter, self._spin_counter)

        # ── QR code preview ───────────────────────────────────────────
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        form.addRow(separator)

        self._lbl_qr = QLabel()
        self._lbl_qr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_qr.setMinimumSize(200, 200)
        self._lbl_qr.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self._lbl_qr.setToolTip("Scan this QR code with any authenticator app")
        form.addRow(self._make_label("QR Code"), self._lbl_qr)

        self._tabs.addTab(manual_tab, "Manual Entry")

        # Connect fields to live QR refresh
        self._edit_name.textChanged.connect(self._refresh_qr)
        self._edit_issuer.textChanged.connect(self._refresh_qr)
        self._edit_secret.textChanged.connect(self._refresh_qr)
        self._combo_algorithm.currentIndexChanged.connect(self._refresh_qr)
        self._spin_digits.valueChanged.connect(self._refresh_qr)
        self._combo_type.currentIndexChanged.connect(self._refresh_qr)
        self._spin_period.valueChanged.connect(self._refresh_qr)
        self._spin_counter.valueChanged.connect(self._refresh_qr)

        # ── Tab 2: URI entry ──────────────────────────────────────────
        uri_tab = QWidget()
        uri_layout = QVBoxLayout(uri_tab)
        uri_layout.setSpacing(12)

        uri_layout.addWidget(self._make_label("Paste otpauth:// URI"))
        self._edit_uri = QLineEdit()
        self._edit_uri.setPlaceholderText("otpauth://totp/Issuer:account?secret=…")
        uri_layout.addWidget(self._edit_uri)

        self._btn_parse_uri = QPushButton("Parse URI")
        self._btn_parse_uri.setObjectName("btn_primary")
        self._btn_parse_uri.clicked.connect(self._parse_uri)
        uri_layout.addWidget(self._btn_parse_uri)

        if self._qr_available:
            self._btn_scan_qr = QPushButton("📷  Scan QR Code (Webcam)")
            self._btn_scan_qr.clicked.connect(self._scan_qr)
            uri_layout.addWidget(self._btn_scan_qr)

            self._btn_scan_file = QPushButton("🖼  Load QR from Image File")
            self._btn_scan_file.clicked.connect(self._scan_file)
            uri_layout.addWidget(self._btn_scan_file)

        uri_layout.addStretch()
        self._tabs.addTab(uri_tab, "QR / URI")

        # ── Buttons ───────────────────────────────────────────────────
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.button(QDialogButtonBox.StandardButton.Save).setObjectName("btn_primary")
        btn_box.accepted.connect(self._on_save)
        btn_box.rejected.connect(self.reject)
        root.addWidget(btn_box)

    def _make_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("lbl_form")
        return lbl

    # ── Slots ─────────────────────────────────────────────────────────

    def _auto_generate_secret(self) -> None:
        """Generate a fresh 20-byte (160-bit) random Base32 secret and fill the field."""
        raw = secrets.token_bytes(20)
        secret = base64.b32encode(raw).decode("ascii").rstrip("=")
        self._edit_secret.setText(secret)
        # Show the generated secret so the user can copy it
        self._edit_secret.setEchoMode(QLineEdit.EchoMode.Normal)
        self._btn_toggle_secret.setChecked(True)
        self._btn_toggle_secret.setText("Hide")

    def _build_otpauth_uri(self) -> str:
        """Build an otpauth:// URI from the current dialog fields."""
        otp_type = self._combo_type.currentData()
        name = self._edit_name.text().strip() or "account"
        issuer = self._edit_issuer.text().strip()
        raw_secret = self._edit_secret.text().strip()
        try:
            secret = normalize_secret(raw_secret) if raw_secret else ""
        except ValueError:
            secret = raw_secret
        algorithm = self._combo_algorithm.currentData().value
        digits = self._spin_digits.value()

        label = quote(f"{issuer}:{name}" if issuer else name)
        uri = f"otpauth://{otp_type}/{label}?secret={secret}"
        if issuer:
            uri += f"&issuer={quote(issuer)}"
        uri += f"&algorithm={algorithm}&digits={digits}"
        if otp_type == "totp":
            uri += f"&period={self._spin_period.value()}"
        else:
            uri += f"&counter={self._spin_counter.value()}"
        return uri

    def _refresh_qr(self) -> None:
        """Re-render the QR code preview from the current field values."""
        try:
            import qrcode
            uri = self._build_otpauth_uri()
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=8,
                border=4,
            )
            qr.add_data(uri)
            qr.make(fit=True)
            matrix = qr.get_matrix()
            n = len(matrix)
            cell = max(1, 200 // n)
            img_size = n * cell
            img = QImage(img_size, img_size, QImage.Format.Format_RGB32)
            img.fill(Qt.GlobalColor.white)
            for r, row in enumerate(matrix):
                for c, val in enumerate(row):
                    if val:
                        for dy in range(cell):
                            for dx in range(cell):
                                img.setPixel(c * cell + dx, r * cell + dy, QColor(0, 0, 0).rgb())
            pixmap = QPixmap.fromImage(img).scaled(
                200, 200,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self._lbl_qr.setPixmap(pixmap)
        except Exception:
            self._lbl_qr.setText("QR unavailable")

    def _toggle_secret_visibility(self, checked: bool) -> None:
        if checked:
            self._edit_secret.setEchoMode(QLineEdit.EchoMode.Normal)
            self._btn_toggle_secret.setText("Hide")
        else:
            self._edit_secret.setEchoMode(QLineEdit.EchoMode.Password)
            self._btn_toggle_secret.setText("Show")

    def _on_type_changed(self, index: int) -> None:
        is_hotp = self._combo_type.currentData() == "hotp"
        self._spin_period.setVisible(not is_hotp)
        self._spin_counter.setVisible(is_hotp)
        self._lbl_counter.setVisible(is_hotp)

    def _parse_uri(self) -> None:
        uri = self._edit_uri.text().strip()
        if not uri:
            QMessageBox.warning(self, "Empty", "Please paste an otpauth:// URI.")
            return
        try:
            parsed = parse_otpauth_uri(uri)
            self._apply_parsed(parsed)
            self._tabs.setCurrentIndex(0)
            QMessageBox.information(self, "Parsed", "URI parsed successfully.")
        except ValueError as exc:
            QMessageBox.critical(self, "Parse Error", str(exc))

    def _apply_parsed(self, parsed) -> None:
        from qr.parser import OTPAuthURI
        self._edit_name.setText(parsed.account_name)
        self._edit_issuer.setText(parsed.issuer)
        self._edit_secret.setText(parsed.secret)
        idx = self._combo_algorithm.findData(parsed.algorithm)
        if idx >= 0:
            self._combo_algorithm.setCurrentIndex(idx)
        self._spin_digits.setValue(parsed.digits)
        type_idx = 0 if parsed.otp_type == "totp" else 1
        self._combo_type.setCurrentIndex(type_idx)
        if parsed.otp_type == "totp":
            self._spin_period.setValue(parsed.period)
        else:
            self._spin_counter.setValue(parsed.counter)

    def _scan_qr(self) -> None:
        """Open webcam scanner dialog."""
        try:
            from ui.qr_scan_dialog import QRScanDialog
            dlg = QRScanDialog(self)
            if dlg.exec() == QDialog.DialogCode.Accepted and dlg.result_uri:
                self._edit_uri.setText(dlg.result_uri)
                self._parse_uri()
        except Exception as exc:
            QMessageBox.critical(self, "Camera Error", str(exc))

    def _scan_file(self) -> None:
        """Load QR code from an image file."""
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Open QR Image", "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif *.tiff)"
        )
        if not path:
            return
        try:
            from qr.scanner import scan_image_file
            uri = scan_image_file(path)
            if uri:
                self._edit_uri.setText(uri)
                self._parse_uri()
            else:
                QMessageBox.warning(self, "Not Found", "No QR code found in the image.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _on_save(self) -> None:
        try:
            account = self._build_account()
        except ValueError as exc:
            QMessageBox.critical(self, "Validation Error", str(exc))
            return

        self.account_saved.emit(account)
        self.accept()

    # ── Validation & building ─────────────────────────────────────────

    def _build_account(self) -> Account:
        name = sanitise_label(self._edit_name.text().strip())
        if not name:
            raise ValueError("Account name is required.")

        raw_secret = self._edit_secret.text().strip()
        if not raw_secret:
            raise ValueError("Secret is required.")
        try:
            secret = normalize_secret(raw_secret)
            decode_secret(secret)  # validate decodable
        except ValueError as exc:
            raise ValueError(f"Invalid secret: {exc}") from exc

        issuer = sanitise_label(self._edit_issuer.text().strip())
        algorithm: Algorithm = self._combo_algorithm.currentData()
        digits = self._spin_digits.value()
        validate_digits(digits)

        otp_type = self._combo_type.currentData()
        period = self._spin_period.value()
        counter = self._spin_counter.value()

        if otp_type == "totp":
            validate_period(period)

        return Account(
            id=self._existing.id if self._existing else None,
            name=name,
            issuer=issuer,
            secret=secret,
            algorithm=algorithm,
            digits=digits,
            period=period,
            otp_type=otp_type,
            counter=counter,
        )

    def _populate(self, account: Account) -> None:
        self._edit_name.setText(account.name)
        self._edit_issuer.setText(account.issuer)
        self._edit_secret.setText(account.secret)
        idx = self._combo_algorithm.findData(account.algorithm)
        if idx >= 0:
            self._combo_algorithm.setCurrentIndex(idx)
        self._spin_digits.setValue(account.digits)
        type_idx = 0 if account.otp_type == "totp" else 1
        self._combo_type.setCurrentIndex(type_idx)
        self._spin_period.setValue(account.period)
        self._spin_counter.setValue(account.counter)
