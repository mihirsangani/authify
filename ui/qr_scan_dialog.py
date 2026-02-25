"""
Live webcam QR-code scan dialog.
"""

import logging
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QImage, QPixmap
from PyQt6.QtWidgets import (
    QDialog,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from qr.scanner import QRScanner

logger = logging.getLogger(__name__)


class QRScanDialog(QDialog):
    """
    Simple QDialog that shows a live webcam feed and emits the decoded URI.
    """

    def __init__(self, parent: Optional[QWidget] = None, camera_index: int = 0) -> None:
        super().__init__(parent)
        self.result_uri: Optional[str] = None
        self._camera_index = camera_index
        self._setup_ui()
        self._start_scanner()

    # ── UI ────────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        self.setWindowTitle("Scan QR Code")
        self.setModal(True)
        self.setMinimumSize(420, 380)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        self._lbl_status = QLabel("Point your webcam at the QR code…")
        self._lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._lbl_status)

        self._lbl_preview = QLabel()
        self._lbl_preview.setFixedSize(380, 280)
        self._lbl_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_preview.setStyleSheet(
            "background:#000; border-radius:8px; color:#7f849c;"
        )
        self._lbl_preview.setText("Camera initialising…")
        layout.addWidget(self._lbl_preview, alignment=Qt.AlignmentFlag.AlignCenter)

        self._btn_cancel = QPushButton("Cancel")
        self._btn_cancel.clicked.connect(self._on_cancel)
        layout.addWidget(self._btn_cancel)

    # ── Scanner ───────────────────────────────────────────────────────

    def _start_scanner(self) -> None:
        try:
            self._scanner = QRScanner(
                on_result=self._on_qr_found,
                camera_index=self._camera_index,
            )
        except Exception as exc:
            self._lbl_status.setText(f"Error: {exc}")
            return

        # Live preview via timer + cv2 (separate from scanner thread)
        self._cap = None
        try:
            import cv2
            self._cap = cv2.VideoCapture(self._camera_index)
        except ImportError:
            pass

        self._scanner.start()

        self._preview_timer = QTimer(self)
        self._preview_timer.timeout.connect(self._update_preview)
        self._preview_timer.start(30)  # ~33 fps

    def _update_preview(self) -> None:
        if self._cap is None or not self._cap.isOpened():
            return
        try:
            import cv2
        except ImportError:
            return
        ret, frame = self._cap.read()
        if not ret:
            return
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = rgb.shape
        qt_img = QImage(rgb.data, w, h, ch * w, QImage.Format.Format_RGB888)
        pix = QPixmap.fromImage(qt_img).scaled(
            380, 280,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._lbl_preview.setPixmap(pix)

    def _on_qr_found(self, uri: str) -> None:
        """Called from scanner thread – schedule UI update on main thread."""
        self.result_uri = uri
        # Use invokeMethod-safe approach: set a flag; timer will pick it up
        QTimer.singleShot(0, self._finish)

    def _finish(self) -> None:
        self._stop_preview()
        self._lbl_status.setText("QR code found!")
        self.accept()

    def _on_cancel(self) -> None:
        self._stop_preview()
        self.reject()

    def _stop_preview(self) -> None:
        if hasattr(self, "_preview_timer"):
            self._preview_timer.stop()
        if hasattr(self, "_scanner"):
            self._scanner.stop()
        if self._cap and self._cap.isOpened():
            self._cap.release()

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._stop_preview()
        super().closeEvent(event)
