"""Tests for /api/set_pin and /api/pin_unlock endpoints."""

import io
import json
import bcrypt
import pytest
from unittest.mock import MagicMock

from app.encryption import aes_gcm_encrypt

TEST_AES_KEY = bytes.fromhex(
    "dbebba31873175ba0513ff7b40304508dbebba31873175ba0513ff7b40304508"
)


@pytest.fixture
def test_key():
    return TEST_AES_KEY


@pytest.fixture
def mock_firestore():
    db = MagicMock()
    db._storage = {}

    def _collection(name):
        col = MagicMock()
        col._name = name
        col._storage = db._storage.setdefault(name, {})

        def _document(doc_id):
            doc = MagicMock()
            doc._id = doc_id

            def _get():
                snap = MagicMock()
                if doc_id in col._storage:
                    snap.exists = True
                    snap.to_dict.return_value = col._storage[doc_id]
                    snap.id = doc_id
                else:
                    snap.exists = False
                    snap.to_dict.return_value = {}
                    snap.id = doc_id
                return snap

            def _set(data):
                col._storage[doc_id] = data

            doc.get = _get
            doc.set = _set
            return doc

        def _add(data):
            col._storage[f"auto_{len(col._storage)}"] = data
            return MagicMock()

        col.document = _document
        col.add = _add
        return col

    db.collection = _collection
    return db


@pytest.fixture
def mock_face_engine():
    engine = MagicMock()
    engine.get_embedding.return_value = [0.0] * 512
    return engine


@pytest.fixture
def app(mock_face_engine, mock_firestore, test_key):
    from app import create_app
    return create_app(
        face_engine=mock_face_engine,
        db=mock_firestore,
        bucket=MagicMock(),
        aes_key=test_key,
        testing=True,
    )


@pytest.fixture
def client(app):
    return app.test_client()


def encrypted_pin(pin_str, key=TEST_AES_KEY):
    return aes_gcm_encrypt(pin_str.encode("utf-8"), key)


# ── Set PIN Tests ───────────────────────────────────────────────────────

class TestSetPin:
    def test_set_valid_pin(self, client, test_key, mock_firestore):
        pin_bytes = encrypted_pin("123456", test_key)
        response = client.post(
            "/api/set_pin?user_id=alice", data=pin_bytes
        )
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "PIN set"

    def test_set_pin_stores_hash(self, client, test_key, mock_firestore):
        pin_bytes = encrypted_pin("987654", test_key)
        client.post("/api/set_pin?user_id=bob", data=pin_bytes)

        stored = mock_firestore._storage["pins"]["bob"]
        assert "hash" in stored
        assert stored["hash"].startswith("$2b$")  # bcrypt prefix

    def test_set_pin_missing_user_id(self, client, test_key):
        pin_bytes = encrypted_pin("123456", test_key)
        response = client.post("/api/set_pin", data=pin_bytes)
        assert response.status_code == 400
        body = json.loads(response.data)
        assert "user_id" in body["error"].lower()

    def test_set_pin_invalid_user_id(self, client, test_key):
        pin_bytes = encrypted_pin("123456", test_key)
        response = client.post(
            "/api/set_pin?user_id=bad/../id", data=pin_bytes
        )
        assert response.status_code == 400

    def test_set_pin_non_digit(self, client, test_key):
        pin_bytes = encrypted_pin("12ab56", test_key)
        response = client.post("/api/set_pin?user_id=charlie", data=pin_bytes)
        assert response.status_code == 400
        body = json.loads(response.data)
        assert "digit" in body["error"].lower()

    def test_set_pin_too_short(self, client, test_key):
        pin_bytes = encrypted_pin("12345", test_key)
        response = client.post("/api/set_pin?user_id=dave", data=pin_bytes)
        assert response.status_code == 400
        body = json.loads(response.data)
        assert "digit" in body["error"].lower()

    def test_set_pin_too_long(self, client, test_key):
        pin_bytes = encrypted_pin("1234567", test_key)
        response = client.post("/api/set_pin?user_id=eve", data=pin_bytes)
        assert response.status_code == 400

    def test_set_pin_corrupted_encryption(self, client):
        response = client.post(
            "/api/set_pin?user_id=frank", data=b"\x00" * 20
        )
        assert response.status_code == 400

    def test_set_pin_empty_body(self, client):
        response = client.post("/api/set_pin?user_id=grace", data=b"")
        assert response.status_code == 400


# ── PIN Unlock Tests ────────────────────────────────────────────────────

class TestPinUnlock:
    def test_pin_unlock_correct(self, client, test_key, mock_firestore):
        # First set the PIN
        pin_bytes = encrypted_pin("040206", test_key)
        client.post("/api/set_pin?user_id=hank", data=pin_bytes)

        # Now unlock with the same PIN
        response = client.post(
            "/api/pin_unlock?user_id=hank", data=pin_bytes
        )
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "UNLOCK"
        assert body["method"] == "PIN"

    def test_pin_unlock_wrong_pin(self, client, test_key, mock_firestore):
        pin_bytes = encrypted_pin("123456", test_key)
        client.post("/api/set_pin?user_id=ivan", data=pin_bytes)

        wrong_bytes = encrypted_pin("654321", test_key)
        response = client.post(
            "/api/pin_unlock?user_id=ivan", data=wrong_bytes
        )
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "DENIED"

    def test_pin_unlock_user_not_found(self, client, test_key):
        pin_bytes = encrypted_pin("123456", test_key)
        response = client.post(
            "/api/pin_unlock?user_id=nobody", data=pin_bytes
        )
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "DENIED"

    def test_pin_unlock_missing_user_id(self, client, test_key):
        pin_bytes = encrypted_pin("123456", test_key)
        response = client.post("/api/pin_unlock", data=pin_bytes)
        assert response.status_code == 400

    def test_pin_unlock_corrupted_encryption(self, client):
        response = client.post(
            "/api/pin_unlock?user_id=julia", data=b"\x00" * 20
        )
        assert response.status_code == 400

    def test_pin_unlock_empty_body(self, client):
        response = client.post("/api/pin_unlock?user_id=kate", data=b"")
        assert response.status_code == 400

    def test_pin_unlock_logs_attempt(self, client, test_key, mock_firestore):
        pin_bytes = encrypted_pin("111222", test_key)
        client.post("/api/set_pin?user_id=leo", data=pin_bytes)
        client.post("/api/pin_unlock?user_id=leo", data=pin_bytes)

        assert "logs" in mock_firestore._storage
        assert len(mock_firestore._storage["logs"]) >= 1

    def test_pin_unlock_denied_logs_attempt(self, client, test_key, mock_firestore):
        pin_bytes = encrypted_pin("999888", test_key)
        client.post("/api/set_pin?user_id=mia", data=pin_bytes)

        wrong_bytes = encrypted_pin("111111", test_key)
        client.post("/api/pin_unlock?user_id=mia", data=wrong_bytes)

        logs = mock_firestore._storage.get("logs", {})
        assert len(logs) >= 1
        log = list(logs.values())[0]
        assert log.get("success") is False

    def test_set_pin_overwrites_existing(self, client, test_key, mock_firestore):
        old_bytes = encrypted_pin("111111", test_key)
        new_bytes = encrypted_pin("222222", test_key)
        client.post("/api/set_pin?user_id=nina", data=old_bytes)

        old_hash = mock_firestore._storage["pins"]["nina"]["hash"]
        client.post("/api/set_pin?user_id=nina", data=new_bytes)
        new_hash = mock_firestore._storage["pins"]["nina"]["hash"]

        assert old_hash != new_hash
        assert bcrypt.checkpw(b"222222", new_hash.encode("utf-8"))
