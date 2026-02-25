"""Tests for authify.storage.database and authify.storage.encryption."""

import json
import tempfile
from pathlib import Path

import pytest

from core.crypto import derive_key, generate_salt
from core.totp import Algorithm
from storage.database import Account, AccountDatabase
from storage.encryption import FieldEncryptor


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db(tmp_path: Path) -> AccountDatabase:
    """Return a fresh in-memory-style database with an encryptor."""
    db = AccountDatabase(db_path=tmp_path / "test.db")
    salt = generate_salt()
    db.set_salt(salt)
    key = derive_key("test_password_123", salt)
    enc = FieldEncryptor(key)
    db.set_encryptor(enc)
    return db


@pytest.fixture()
def sample_account() -> Account:
    return Account(
        name="alice@example.com",
        secret="JBSWY3DPEHPK3PXP",
        issuer="GitHub",
        algorithm=Algorithm.SHA1,
        digits=6,
        period=30,
        otp_type="totp",
    )


# ── Salt / meta ───────────────────────────────────────────────────────────────

def test_fresh_db_no_salt(tmp_path: Path) -> None:
    db = AccountDatabase(db_path=tmp_path / "fresh.db")
    assert db.get_salt() is None
    assert not db.has_master_password()
    db.close()


def test_set_and_get_salt(tmp_path: Path) -> None:
    db = AccountDatabase(db_path=tmp_path / "salt.db")
    salt = generate_salt()
    db.set_salt(salt)
    assert db.get_salt() == salt
    assert db.has_master_password()
    db.close()


# ── CRUD ──────────────────────────────────────────────────────────────────────

def test_add_and_get_account(tmp_db: AccountDatabase, sample_account: Account) -> None:
    acc_id = tmp_db.add_account(sample_account)
    assert acc_id is not None

    retrieved = tmp_db.get_account(acc_id)
    assert retrieved is not None
    assert retrieved.name == sample_account.name
    assert retrieved.issuer == sample_account.issuer
    assert retrieved.secret == sample_account.secret
    assert retrieved.algorithm == Algorithm.SHA1
    assert retrieved.digits == 6


def test_list_accounts(tmp_db: AccountDatabase, sample_account: Account) -> None:
    tmp_db.add_account(sample_account)
    tmp_db.add_account(Account(name="bob", secret="JBSWY3DPEHPK3PXP", issuer="Discord"))
    accounts = tmp_db.list_accounts()
    assert len(accounts) == 2


def test_update_account(tmp_db: AccountDatabase, sample_account: Account) -> None:
    acc_id = tmp_db.add_account(sample_account)
    acc = tmp_db.get_account(acc_id)
    acc.name = "updated@example.com"
    tmp_db.update_account(acc)

    updated = tmp_db.get_account(acc_id)
    assert updated.name == "updated@example.com"


def test_delete_account(tmp_db: AccountDatabase, sample_account: Account) -> None:
    acc_id = tmp_db.add_account(sample_account)
    tmp_db.delete_account(acc_id)
    assert tmp_db.get_account(acc_id) is None
    assert len(tmp_db.list_accounts()) == 0


def test_update_hotp_counter(tmp_db: AccountDatabase) -> None:
    acc = Account(
        name="hotp_test", secret="JBSWY3DPEHPK3PXP",
        otp_type="hotp", counter=0,
    )
    acc_id = tmp_db.add_account(acc)
    tmp_db.update_hotp_counter(acc_id, 5)
    retrieved = tmp_db.get_account(acc_id)
    assert retrieved.counter == 5


# ── Export / Import ───────────────────────────────────────────────────────────

def test_export_import_roundtrip(tmp_db: AccountDatabase, sample_account: Account) -> None:
    tmp_db.add_account(sample_account)
    exported = tmp_db.export_json()

    data = json.loads(exported)
    assert len(data["accounts"]) == 1
    assert data["accounts"][0]["name"] == sample_account.name

    count = tmp_db.import_json(exported)
    assert count == 1
    assert len(tmp_db.list_accounts()) == 2  # original + imported


# ── Encryption correctness ────────────────────────────────────────────────────

def test_wrong_key_cannot_decrypt(tmp_path: Path, sample_account: Account) -> None:
    """A database unlocked with the wrong key should raise on list."""
    db = AccountDatabase(db_path=tmp_path / "enc.db")
    salt = generate_salt()
    db.set_salt(salt)
    correct_key = derive_key("correct_password", salt)
    db.set_encryptor(FieldEncryptor(correct_key))
    db.add_account(sample_account)
    db.close()

    # Re-open with wrong key
    db2 = AccountDatabase(db_path=tmp_path / "enc.db")
    wrong_key = derive_key("wrong_password", salt)
    db2.set_encryptor(FieldEncryptor(wrong_key))

    with pytest.raises(Exception):
        db2.list_accounts()

    db2.close()
