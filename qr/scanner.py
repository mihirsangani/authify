"""
Webcam-based QR code scanner for Authify.

Uses OpenCV for frame capture and pyzbar for decoding.
Falls back gracefully when the libraries are unavailable.
"""

import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def _check_deps() -> tuple[bool, str]:
    """Return (available, message) for optional scanning deps."""
    try:
        import cv2  # noqa: F401
        from pyzbar import pyzbar  # noqa: F401
        return True, ""
    except ImportError as exc:
        return False, str(exc)


class QRScanner:
    """
    Continuous webcam QR scanner.

    Usage::

        scanner = QRScanner(on_result=handle_uri)
        scanner.start()   # non-blocking, runs in a thread
        ...
        scanner.stop()
    """

    def __init__(
        self,
        on_result: Callable[[str], None],
        camera_index: int = 0,
    ) -> None:
        """
        Args:
            on_result:    Callback invoked with the decoded string when a QR
                          code is found. Called from the scanning thread.
            camera_index: OpenCV camera index (default 0 = first webcam).
        """
        self._on_result = on_result
        self._camera_index = camera_index
        self._running = False
        self._thread: Optional["threading.Thread"] = None

    # ── Public API ───────────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        """True if opencv-python and pyzbar are installed."""
        return _check_deps()[0]

    def start(self) -> None:
        """Start scanning in a background daemon thread."""
        if not self.is_available:
            available, msg = _check_deps()
            raise RuntimeError(
                f"QR scanning requires opencv-python and pyzbar: {msg}"
            )
        if self._running:
            return
        import threading

        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the scanning thread to stop."""
        self._running = False

    # ── Internal ─────────────────────────────────────────────────────────

    def _scan_loop(self) -> None:
        """Main scanning loop; runs in a daemon thread."""
        import cv2
        from pyzbar import pyzbar

        cap = cv2.VideoCapture(self._camera_index)
        if not cap.isOpened():
            logger.error("Cannot open camera index %d", self._camera_index)
            self._running = False
            return

        seen: set[str] = set()

        try:
            while self._running:
                ret, frame = cap.read()
                if not ret:
                    continue

                codes = pyzbar.decode(frame)
                for code in codes:
                    if code.type != "QRCODE":
                        continue
                    data = code.data.decode("utf-8", errors="ignore")
                    if data.startswith("otpauth://") and data not in seen:
                        seen.add(data)
                        try:
                            self._on_result(data)
                        except Exception:
                            logger.exception("on_result callback raised an exception")
                        self._running = False  # stop after first valid code
                        break
        finally:
            cap.release()


def scan_image_file(path: str) -> Optional[str]:
    """
    Decode the first QR code from an image file.

    Args:
        path: Path to the image file.

    Returns:
        Decoded string, or None if no QR code found.

    Raises:
        RuntimeError: If dependencies are unavailable.
        FileNotFoundError: If the image file does not exist.
    """
    available, msg = _check_deps()
    if not available:
        raise RuntimeError(
            f"QR scanning requires opencv-python and pyzbar: {msg}"
        )

    import cv2
    from pyzbar import pyzbar
    import os

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Image not found: {path}")

    img = cv2.imread(path)
    if img is None:
        raise ValueError(f"Could not read image: {path}")

    codes = pyzbar.decode(img)
    for code in codes:
        if code.type == "QRCODE":
            return code.data.decode("utf-8", errors="ignore")
    return None
