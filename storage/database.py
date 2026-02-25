"""
SQLite-backed account store with field-level AES-256-GCM encryption.

Schema
------
accounts
  id       INTEGER  PRIMARY KEY AUTOINCREMENT
  name     TEXT     NOT NULL   -- encrypted issuer:account label
  issuer   TEXT                -- encrypted issuer
  secret   TEXT     NOT NULL   -- encrypted base32 secret
  algorithm TEXT    NOT NULL   -- encrypted (SHA1/SHA256/SHA512)
  digits   INTEGER  NOT NULL   -- encrypted (6/8)
  period   INTEGER  NOT NULL   -- encrypted (30/custom)
  otp_type TEXT     NOT NULL   -- encrypted (totp/hotp)
  counter  INTEGER             -- encrypted HOTP counter (NULL for TOTP)

meta
  key      TEXT PRIMARY KEY
  value    TEXT                -- salt stored as hex (NOT encrypted)
"""

import json
import os
import sqlite3
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

from core import crypto
from core.totp import Algorithm
from storage.encryption import FieldEncryptor


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Account:
    """Represents a single TOTP/HOTP account."""

    name: str
    secret: str           # base32-encoded (normalised)
    issuer: str = ""
    algorithm: Algorithm = Algorithm.SHA1
    digits: int = 6
    period: int = 30
    otp_type: str = "totp"
    counter: int = 0
    id: Optional[int] = None


# ── Database ──────────────────────────────────────────────────────────────────

class AccountDatabase:
    """Thread-safe SQLite store with transparent field encryption."""

    # Default location: %APPDATA%\authify\authify.db  (Windows)
    #                   ~/.local/share/authify/authify.db  (Linux/macOS)
    _DEFAULT_DIR = Path(
        os.environ.get("APPDATA", Path.home() / ".local" / "share")
    ) / "authify"

    def __init__(
        self,
        db_path: Optional[Path] = None,
        encryptor: Optional[FieldEncryptor] = None,
    ) -> None:
        """
        Args:
            db_path:   Path to the SQLite file.  Defaults to
                       ``%APPDATA%/authify/authify.db``.
            encryptor: :class:`~authify.storage.encryption.FieldEncryptor`
                       instance.  Pass None only for read-only / unencrypted
                       debug use.
        """
        self._path = db_path or (self._DEFAULT_DIR / "authify.db")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._encryptor = encryptor
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._bootstrap()

    # ── Schema ───────────────────────────────────────────────────────────

    def _bootstrap(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    name      TEXT    NOT NULL,
                    issuer    TEXT    NOT NULL DEFAULT '',
                    secret    TEXT    NOT NULL,
                    algorithm TEXT    NOT NULL DEFAULT 'SHA1',
                    digits    INTEGER NOT NULL DEFAULT 6,
                    period    INTEGER NOT NULL DEFAULT 30,
                    otp_type  TEXT    NOT NULL DEFAULT 'totp',
                    counter   INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    # ── Salt / meta ───────────────────────────────────────────────────────

    def get_salt(self) -> Optional[bytes]:
        """Return stored salt or None if database is fresh."""
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='salt'"
        ).fetchone()
        return bytes.fromhex(row["value"]) if row else None

    def set_salt(self, salt: bytes) -> None:
        """Persist the salt (stored as hex, NOT encrypted)."""
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('salt', ?)",
                (salt.hex(),),
            )

    def has_master_password(self) -> bool:
        """Return True if a salt (and thus a master password) has been set."""
        return self.get_salt() is not None

    # ── Encryptor ─────────────────────────────────────────────────────────

    def set_encryptor(self, encryptor: FieldEncryptor) -> None:
        """Attach or replace the field encryptor after unlock."""
        self._encryptor = encryptor

    def _enc(self, value: str) -> str:
        if self._encryptor is None:
            raise RuntimeError("Database is locked – no encryptor set.")
        return self._encryptor.encrypt_field(value)

    def _dec(self, value: str) -> str:
        if self._encryptor is None:
            raise RuntimeError("Database is locked – no encryptor set.")
        return self._encryptor.decrypt_field(value)

    # ── CRUD ──────────────────────────────────────────────────────────────

    def add_account(self, account: Account) -> int:
        """Encrypt and insert an account; return the new row id."""
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO accounts
                    (name, issuer, secret, algorithm, digits, period, otp_type, counter)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._enc(account.name),
                    self._enc(account.issuer),
                    self._enc(account.secret),
                    self._enc(account.algorithm.value if isinstance(account.algorithm, Algorithm) else account.algorithm),
                    self._enc(str(account.digits)),
                    self._enc(str(account.period)),
                    self._enc(account.otp_type),
                    self._enc(str(account.counter)),
                ),
            )
        return cursor.lastrowid  # type: ignore[return-value]

    def get_account(self, account_id: int) -> Optional[Account]:
        """Fetch and decrypt a single account by id."""
        row = self._conn.execute(
            "SELECT * FROM accounts WHERE id=?", (account_id,)
        ).fetchone()
        return self._row_to_account(row) if row else None

    def list_accounts(self) -> List[Account]:
        """Return all accounts, decrypted."""
        rows = self._conn.execute(
            "SELECT * FROM accounts ORDER BY id"
        ).fetchall()
        return [self._row_to_account(r) for r in rows]

    def update_account(self, account: Account) -> None:
        """Re-encrypt and update an existing account."""
        if account.id is None:
            raise ValueError("Cannot update account without id.")
        with self._conn:
            self._conn.execute(
                """
                UPDATE accounts SET
                    name=?, issuer=?, secret=?, algorithm=?,
                    digits=?, period=?, otp_type=?, counter=?
                WHERE id=?
                """,
                (
                    self._enc(account.name),
                    self._enc(account.issuer),
                    self._enc(account.secret),
                    self._enc(account.algorithm.value if isinstance(account.algorithm, Algorithm) else account.algorithm),
                    self._enc(str(account.digits)),
                    self._enc(str(account.period)),
                    self._enc(account.otp_type),
                    self._enc(str(account.counter)),
                    account.id,
                ),
            )

    def delete_account(self, account_id: int) -> None:
        """Delete an account by id."""
        with self._conn:
            self._conn.execute(
                "DELETE FROM accounts WHERE id=?", (account_id,)
            )

    def update_hotp_counter(self, account_id: int, counter: int) -> None:
        """Update HOTP counter after a valid token use."""
        row = self._conn.execute(
            "SELECT counter FROM accounts WHERE id=?", (account_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Account {account_id} not found.")
        with self._conn:
            self._conn.execute(
                "UPDATE accounts SET counter=? WHERE id=?",
                (self._enc(str(counter)), account_id),
            )

    # ── Export / Import ───────────────────────────────────────────────────

    def export_json(self) -> str:
        """Export all accounts as a JSON string (secrets in plaintext)."""
        accounts = self.list_accounts()
        data = []
        for acc in accounts:
            data.append({
                "name": acc.name,
                "issuer": acc.issuer,
                "secret": acc.secret,
                "algorithm": acc.algorithm.value if isinstance(acc.algorithm, Algorithm) else acc.algorithm,
                "digits": acc.digits,
                "period": acc.period,
                "otp_type": acc.otp_type,
                "counter": acc.counter,
            })
        return json.dumps({"accounts": data}, indent=2)

    def import_json(self, json_str: str) -> int:
        """Import accounts from a JSON string. Returns number imported."""
        data = json.loads(json_str)
        accounts = data.get("accounts", [])
        count = 0
        for item in accounts:
            try:
                acc = Account(
                    name=item["name"],
                    secret=item["secret"],
                    issuer=item.get("issuer", ""),
                    algorithm=Algorithm(item.get("algorithm", "SHA1")),
                    digits=int(item.get("digits", 6)),
                    period=int(item.get("period", 30)),
                    otp_type=item.get("otp_type", "totp"),
                    counter=int(item.get("counter", 0)),
                )
                self.add_account(acc)
                count += 1
            except Exception:
                pass
        return count

    # ── Internals ─────────────────────────────────────────────────────────

    def _row_to_account(self, row: sqlite3.Row) -> Account:
        return Account(
            id=row["id"],
            name=self._dec(row["name"]),
            issuer=self._dec(row["issuer"]),
            secret=self._dec(row["secret"]),
            algorithm=Algorithm(self._dec(row["algorithm"])),
            digits=int(self._dec(row["digits"])),
            period=int(self._dec(row["period"])),
            otp_type=self._dec(row["otp_type"]),
            counter=int(self._dec(row["counter"])),
        )

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
