"""Tests for /api/register and /api/unlock endpoints.

Follows TDD: tests define the contract before implementation exists.
All Firestore and GCS interactions are mocked for deterministic testing.
"""

import os
import io
import json
import numpy as np
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from app.encryption import aes_gcm_encrypt
from app.similarity import cosine_similarity

# 32-byte AES-256 key for test encryption
TEST_AES_KEY = bytes.fromhex(
    "dbebba31873175ba0513ff7b40304508dbebba31873175ba0513ff7b40304508"
)


@pytest.fixture
def test_key():
    return TEST_AES_KEY


@pytest.fixture
def sample_plaintext_jpeg():
    """Real-world size test JPEG bytes (~60KB, resembles a face image)."""
    return os.urandom(60 * 1024)


@pytest.fixture
def encrypted_jpeg(sample_plaintext_jpeg, test_key):
    """AES-GCM encrypted sample JPEG."""
    return aes_gcm_encrypt(sample_plaintext_jpeg, test_key)


@pytest.fixture
def mock_face_embedding():
    """A realistic 512-dim L2-normalized embedding vector."""
    rng = np.random.default_rng(42)
    emb = rng.normal(0, 1, 512)
    emb = emb / np.linalg.norm(emb)
    return emb.tolist()


@pytest.fixture
def mock_face_engine(mock_face_embedding):
    """Mock FaceEngine that returns a fixed embedding for any image."""
    engine = MagicMock()
    engine.get_embedding.return_value = mock_face_embedding
    engine.detect.return_value = [{"bbox": [10, 10, 200, 200], "det_score": 0.95}]
    return engine


@pytest.fixture
def mock_face_engine_no_face():
    """Mock FaceEngine that returns None for all images (no face found)."""
    engine = MagicMock()
    engine.get_embedding.return_value = None
    engine.detect.return_value = []
    return engine


@pytest.fixture
def mock_firestore():
    """Mock Firestore client with dict-based storage backing.

    Stores documents in a simple nested dict so that set/stream/get are
    internally consistent. This lets us test that register writes correct
    data and unlock reads it back.
    """
    db = MagicMock()
    db._storage = {}  # {collection_name: {doc_id: {data}}}

    def _collection(name):
        col = MagicMock()
        col._name = name
        col._storage = db._storage.setdefault(name, {})

        def _document(doc_id):
            doc = MagicMock()
            doc._id = doc_id
            doc._name = name

            def _set(data):
                doc._data = data
                col._storage[doc_id] = data
                return None

            def _delete():
                col._storage.pop(doc_id, None)
                return None

            def _get():
                snap = MagicMock()
                if doc_id in col._storage:
                    snap.exists = True
                    snap.to_dict.return_value = col._storage[doc_id]
                    snap.id = doc_id
                else:
                    snap.exists = False
                    snap.to_dict.return_value = None
                    snap.id = doc_id
                return snap

            doc.set = _set
            doc.get = _get
            doc.delete = _delete
            doc._data = col._storage.get(doc_id, {})
            return doc

        def _stream():
            """Yield DocumentSnapshot-like mocks for all stored docs."""
            snapshots = []
            for doc_id, data in col._storage.items():
                snap = MagicMock()
                snap.to_dict.return_value = data
                snap.id = doc_id
                snapshots.append(snap)
            return snapshots

        def _add(data):
            doc_id = f"auto_{len(col._storage)}"
            doc = MagicMock()
            doc.id = doc_id
            col._storage[doc_id] = data
            return doc

        col.document = _document
        col.stream = _stream
        col.add = _add
        return col

    db.collection = _collection
    return db


@pytest.fixture
def mock_bucket():
    """Mock GCS bucket with blob operations."""
    bucket = MagicMock()
    blob_mock = MagicMock()
    blob_mock.upload_from_string = MagicMock()
    blob_mock.public_url = f"https://storage.googleapis.com/test-bucket/log.jpg"

    def _blob(path):
        blob_mock._path = path
        return blob_mock

    bucket.blob = MagicMock(side_effect=_blob)
    return bucket


@pytest.fixture
def app(mock_face_engine, mock_firestore, mock_bucket, test_key):
    """Create a Flask test app with all dependencies injected."""
    from app import create_app
    flask_app = create_app(
        face_engine=mock_face_engine,
        db=mock_firestore,
        bucket=mock_bucket,
        aes_key=test_key,
        testing=True,
    )
    return flask_app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


# ─── Registration Tests ───────────────────────────────────────────────

class TestRegisterEndpoint:
    def test_register_success_returns_200(self, client, encrypted_jpeg):
        response = client.post(
            "/api/register",
            data={
                "user_id": "user_001",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "Face registered"
        assert body["user_id"] == "user_001"

    def test_register_stores_embeddings_in_firestore(
        self, client, encrypted_jpeg, mock_firestore
    ):
        client.post(
            "/api/register",
            data={
                "user_id": "user_002",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        stored = mock_firestore._storage["users"]["user_002"]
        assert "image1" in stored
        assert "image2" in stored
        assert "image3" in stored
        assert "image4" in stored
        assert "image5" in stored
        # Each embedding should be 512 floats
        for key in ["image1", "image2", "image3", "image4", "image5"]:
            emb = stored[key]
            assert isinstance(emb, list)
            assert len(emb) == 512

    def test_register_missing_user_id_returns_400(self, client, encrypted_jpeg):
        response = client.post(
            "/api/register",
            data={
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        body = json.loads(response.data)
        assert "error" in body

    def test_register_empty_user_id_returns_400(self, client, encrypted_jpeg):
        response = client.post(
            "/api/register",
            data={
                "user_id": "",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 400

    def test_register_user_id_with_special_chars_returns_400(
        self, client, encrypted_jpeg
    ):
        response = client.post(
            "/api/register",
            data={
                "user_id": "user/../../malicious",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 400

    def test_register_missing_image_returns_400(self, client, encrypted_jpeg):
        response = client.post(
            "/api/register",
            data={
                "user_id": "user_003",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                # Missing image2-image5
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        body = json.loads(response.data)
        assert "image" in body.get("error", "").lower()

    def test_register_no_face_detected_returns_400(self, test_key):
        """When FaceEngine returns None for any image, reject registration."""
        from app import create_app

        no_face_engine = MagicMock()
        no_face_engine.get_embedding.return_value = None

        mock_db = MagicMock()
        mock_db._storage = {}
        mock_db.collection = MagicMock()

        app = create_app(
            face_engine=no_face_engine,
            db=mock_db,
            bucket=MagicMock(),
            aes_key=test_key,
            testing=True,
        )
        client = app.test_client()

        plaintext = os.urandom(4096)
        encrypted = aes_gcm_encrypt(plaintext, test_key)

        response = client.post(
            "/api/register",
            data={
                "user_id": "user_004",
                "image1": (io.BytesIO(encrypted), "image1.jpg"),
                "image2": (io.BytesIO(encrypted), "image2.jpg"),
                "image3": (io.BytesIO(encrypted), "image3.jpg"),
                "image4": (io.BytesIO(encrypted), "image4.jpg"),
                "image5": (io.BytesIO(encrypted), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        body = json.loads(response.data)
        assert "face" in body.get("error", "").lower()

    def test_register_corrupted_encryption_returns_400(self, client, test_key):
        """Arbitrary garbage (not valid AES-GCM) should fail."""
        response = client.post(
            "/api/register",
            data={
                "user_id": "user_005",
                "image1": (io.BytesIO(b"\x00" * 100), "image1.jpg"),
                "image2": (io.BytesIO(b"\x00" * 100), "image2.jpg"),
                "image3": (io.BytesIO(b"\x00" * 100), "image3.jpg"),
                "image4": (io.BytesIO(b"\x00" * 100), "image4.jpg"),
                "image5": (io.BytesIO(b"\x00" * 100), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 400

    def test_register_long_user_id_returns_400(self, client, encrypted_jpeg):
        response = client.post(
            "/api/register",
            data={
                "user_id": "x" * 101,
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 400


# ─── Unlock Tests ─────────────────────────────────────────────────────

class TestUnlockEndpoint:
    def test_unlock_high_confidence(self, client, encrypted_jpeg, mock_firestore):
        """Pre-register a user, then unlock with HIGH confidence (>0.75)."""
        # First register a user so they exist in mock storage
        client.post(
            "/api/register",
            data={
                "user_id": "alice",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )

        # Unlock: the mock FaceEngine always returns the SAME embedding
        # (from mock_face_embedding fixture), so similarity will be ~1.0
        response = client.post("/api/unlock", data=encrypted_jpeg)
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "UNLOCK"
        assert body["confidence"] == "HIGH"
        assert body["similarity"] >= 0.75

    def test_unlock_no_match_returns_no_match(self, client, encrypted_jpeg):
        """When no users are registered, unlock should return NO_MATCH."""
        response = client.post("/api/unlock", data=encrypted_jpeg)
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "NO_MATCH"

    def test_unlock_no_face_returns_400(self, test_key):
        """When no face is detected in the image, return 400."""
        from app import create_app

        no_face_engine = MagicMock()
        no_face_engine.get_embedding.return_value = None
        mock_db = MagicMock()
        mock_db._storage = {"users": {}}
        mock_db.collection = MagicMock()

        app = create_app(
            face_engine=no_face_engine,
            db=mock_db,
            bucket=MagicMock(),
            aes_key=test_key,
            testing=True,
        )
        client = app.test_client()

        plaintext = os.urandom(4096)
        encrypted = aes_gcm_encrypt(plaintext, test_key)
        response = client.post("/api/unlock", data=encrypted)
        assert response.status_code == 400

    def test_unlock_corrupted_payload_returns_400(self, client):
        """Non-AES-GCM payload should fail with 400."""
        response = client.post("/api/unlock", data=b"\x00" * 50)
        assert response.status_code == 400

    def test_unlock_empty_body_returns_400(self, client):
        response = client.post("/api/unlock", data=b"")
        assert response.status_code == 400

    def test_unlock_tampered_payload_returns_400(self, client, test_key):
        """A valid AES-GCM packet with a flipped bit should fail."""
        plaintext = os.urandom(4096)
        encrypted = aes_gcm_encrypt(plaintext, test_key)
        tampered = bytearray(encrypted)
        tampered[30] ^= 0xFF  # flip a bit in ciphertext/tag
        response = client.post("/api/unlock", data=bytes(tampered))
        assert response.status_code == 400

    def test_unlock_wrong_key_returns_400(self, test_key, mock_face_engine):
        """Encrypt with a different key than the server's key."""
        from app import create_app

        wrong_key = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        plaintext = os.urandom(4096)
        encrypted_with_wrong_key = aes_gcm_encrypt(plaintext, wrong_key)
        mock_db = MagicMock()
        mock_db._storage = {"users": {}}
        mock_db.collection = MagicMock()

        app = create_app(
            face_engine=mock_face_engine,
            db=mock_db,
            bucket=MagicMock(),
            aes_key=test_key,  # server uses different key
            testing=True,
        )
        client = app.test_client()
        response = client.post("/api/unlock", data=encrypted_with_wrong_key)
        assert response.status_code == 400

    def test_unlock_logs_to_firestore_on_success(
        self, client, encrypted_jpeg, mock_firestore
    ):
        """HIGH confidence unlock must write to Firestore logs collection."""
        client.post(
            "/api/register",
            data={
                "user_id": "bob",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        client.post("/api/unlock", data=encrypted_jpeg)

        # Check that at least one log entry was created
        logs_storage = mock_firestore._storage.get("logs", {})
        assert len(logs_storage) >= 1
        log = list(logs_storage.values())[0]
        assert log["user_id"] == "bob"
        assert log["similarity"] >= 0.75
        assert "image_url" in log

    def test_unlock_logs_to_gcs_on_success(
        self, client, encrypted_jpeg, mock_firestore, mock_bucket
    ):
        """HIGH confidence unlock must upload the image to GCS."""
        client.post(
            "/api/register",
            data={
                "user_id": "charlie",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        client.post("/api/unlock", data=encrypted_jpeg)

        assert mock_bucket.blob.call_count >= 1
        call_path = mock_bucket.blob.call_args[0][0]
        assert call_path.startswith("logs/charlie/")

    def test_unlock_no_match_does_not_log(self, client, encrypted_jpeg, mock_firestore):
        """NO_MATCH should NOT write to logs or GCS."""
        response = client.post("/api/unlock", data=encrypted_jpeg)
        assert response.status_code == 200
        logs_storage = mock_firestore._storage.get("logs", {})
        assert len(logs_storage) == 0

    def test_unlock_records_similarity_and_confidence(
        self, client, encrypted_jpeg, mock_firestore
    ):
        """Verify the response contains exact similarity and confidence."""
        client.post(
            "/api/register",
            data={
                "user_id": "dave",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        response = client.post("/api/unlock", data=encrypted_jpeg)
        body = json.loads(response.data)
        assert "similarity" in body
        assert "confidence" in body
        assert body["similarity"] > 0.9  # same embedding → near 1.0
        assert body["confidence"] in ("HIGH", "MEDIUM-HIGH", "MEDIUM")

    def test_unlock_similarity_value_is_float(self, client, encrypted_jpeg):
        """Similarity must be a numeric float, not a string."""
        client.post(
            "/api/register",
            data={
                "user_id": "eve",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        response = client.post("/api/unlock", data=encrypted_jpeg)
        body = json.loads(response.data)
        assert isinstance(body["similarity"], (int, float))

    def test_unlock_no_match_returns_similarity_zero(self, client, encrypted_jpeg):
        """When no users exist, similarity should be 0."""
        response = client.post("/api/unlock", data=encrypted_jpeg)
        body = json.loads(response.data)
        assert body["status"] == "NO_MATCH"
        assert body["similarity"] == 0.0

    def test_register_overwrites_existing_user(self, client, encrypted_jpeg, mock_firestore):
        """Registering the same user_id twice overwrites the previous data."""
        client.post(
            "/api/register",
            data={
                "user_id": "overwrite_test",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        first_set = mock_firestore._storage["users"]["overwrite_test"].copy()

        # Register again
        client.post(
            "/api/register",
            data={
                "user_id": "overwrite_test",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        second_set = mock_firestore._storage["users"]["overwrite_test"]
        # Embeddings should match (same mock returns same values)
        assert second_set["image1"] == first_set["image1"]


# ─── Health Check Tests ────────────────────────────────────────────────

class TestHealthCheck:
    def test_health_returns_200(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "ok"


# ─── Content Type Tests ────────────────────────────────────────────────

class TestContentTypeValidation:
    def test_register_with_json_body_returns_400(self, client):
        """Register must use multipart/form-data, not JSON."""
        response = client.post(
            "/api/register",
            data=json.dumps({"user_id": "test"}),
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_unlock_with_json_body_returns_400(self, client):
        """Unlock expects raw encrypted bytes, not JSON."""
        response = client.post(
            "/api/unlock",
            data=json.dumps({"image": "base64"}),
            content_type="application/json",
        )
        assert response.status_code == 400


# ─── Remove User Tests ──────────────────────────────────────────────────

class TestRemoveUserEndpoint:
    def test_remove_user_success(self, client, encrypted_jpeg, mock_firestore):
        """Register a user, then delete them and verify users document is gone."""
        # Register a user first
        client.post(
            "/api/register",
            data={
                "user_id": "delete_me",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        assert "delete_me" in mock_firestore._storage.get("users", {})

        # Delete the user
        response = client.delete("/api/user?user_id=delete_me")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "User deleted"
        assert body["user_id"] == "delete_me"

        # Verify users document is gone
        assert "delete_me" not in mock_firestore._storage.get("users", {})

    def test_remove_user_with_pin(self, client, encrypted_jpeg, mock_firestore, test_key):
        """Register user + set PIN, then delete, verify both users and pins deleted."""
        # Register user
        client.post(
            "/api/register",
            data={
                "user_id": "user_with_pin",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )

        # Set a PIN
        pin_data = aes_gcm_encrypt(b"123456", test_key)
        client.post("/api/set_pin?user_id=user_with_pin", data=pin_data)

        assert "user_with_pin" in mock_firestore._storage.get("users", {})
        assert "user_with_pin" in mock_firestore._storage.get("pins", {})

        # Delete the user
        response = client.delete("/api/user?user_id=user_with_pin")
        assert response.status_code == 200

        # Verify both collections are cleaned up
        assert "user_with_pin" not in mock_firestore._storage.get("users", {})
        assert "user_with_pin" not in mock_firestore._storage.get("pins", {})

    def test_remove_nonexistent_user(self, client, mock_firestore):
        """Deleting a nonexistent user should return 200 (idempotent)."""
        response = client.delete("/api/user?user_id=nobody")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["status"] == "User deleted"
        assert body["user_id"] == "nobody"

    def test_remove_user_missing_user_id(self, client):
        """No user_id param should return 400."""
        response = client.delete("/api/user")
        assert response.status_code == 400
        body = json.loads(response.data)
        assert "user_id" in body["error"].lower()

    def test_remove_user_invalid_user_id(self, client):
        """user_id with special characters should return 400."""
        response = client.delete("/api/user?user_id=../etc")
        assert response.status_code == 400
        body = json.loads(response.data)
        assert "user_id" in body["error"].lower()


# ─── Logs Retrieval Tests ────────────────────────────────────────────────

class TestLogsEndpoint:
    def test_logs_empty(self, client):
        """GET /api/logs with no logs returns empty list."""
        response = client.get("/api/logs")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["logs"] == []
        assert body["next_cursor"] is None

    def test_logs_returns_face_unlock_events(
        self, client, encrypted_jpeg, mock_firestore
    ):
        """Simulate a face unlock and verify the log entry is returned."""
        # Register a user
        client.post(
            "/api/register",
            data={
                "user_id": "log_user",
                "image1": (io.BytesIO(encrypted_jpeg), "image1.jpg"),
                "image2": (io.BytesIO(encrypted_jpeg), "image2.jpg"),
                "image3": (io.BytesIO(encrypted_jpeg), "image3.jpg"),
                "image4": (io.BytesIO(encrypted_jpeg), "image4.jpg"),
                "image5": (io.BytesIO(encrypted_jpeg), "image5.jpg"),
            },
            content_type="multipart/form-data",
        )
        # Trigger face unlock (creates a FACE log via _log_event)
        client.post("/api/unlock", data=encrypted_jpeg)

        response = client.get("/api/logs")
        assert response.status_code == 200
        body = json.loads(response.data)
        logs = body["logs"]
        assert len(logs) >= 1

        log = logs[0]
        assert "log_id" in log
        assert log["user_id"] == "log_user"
        assert log["method"] == "FACE"
        assert "similarity" in log
        assert "confidence" in log
        assert "image_url" in log

    def test_logs_filter_by_user_id(self, client, mock_firestore):
        """Add logs for two users, filter by one, verify only that user's logs."""
        mock_firestore._storage["logs"] = {
            "log_a1": {
                "user_id": "alice", "timestamp": 1000.0, "method": "FACE",
                "similarity": 0.95, "confidence": "HIGH",
                "image_url": "http://example.com/a1.jpg",
            },
            "log_a2": {
                "user_id": "alice", "timestamp": 900.0, "method": "FACE",
                "similarity": 0.88, "confidence": "MEDIUM-HIGH",
                "image_url": "http://example.com/a2.jpg",
            },
            "log_b1": {
                "user_id": "bob", "timestamp": 950.0, "method": "PIN",
                "success": True, "image_url": None,
            },
        }

        response = client.get("/api/logs?user_id=alice")
        assert response.status_code == 200
        body = json.loads(response.data)
        logs = body["logs"]
        assert len(logs) == 2
        for log in logs:
            assert log["user_id"] == "alice"
        assert body["next_cursor"] is None

    def test_logs_limit(self, client, mock_firestore):
        """Verify limit parameter caps the number of returned logs."""
        logs_storage = {}
        for i in range(60):
            logs_storage[f"log_{i}"] = {
                "user_id": "test_user",
                "timestamp": float(i * 10),
                "method": "FACE",
                "similarity": 0.9,
                "confidence": "HIGH",
                "image_url": f"http://example.com/{i}.jpg",
            }
        mock_firestore._storage["logs"] = logs_storage

        response = client.get("/api/logs")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert len(body["logs"]) == 50  # default limit
        assert body["next_cursor"] is not None

        # Explicit limit of 25
        response = client.get("/api/logs?limit=25")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert len(body["logs"]) == 25

    def test_logs_pagination(self, client, mock_firestore):
        """Use start_after to paginate through logs."""
        logs_storage = {}
        for i in range(10):
            logs_storage[f"log_{i}"] = {
                "user_id": "test_user",
                "timestamp": float(i * 10),
                "method": "FACE",
                "similarity": 0.9,
                "confidence": "HIGH",
                "image_url": f"http://example.com/{i}.jpg",
            }
        mock_firestore._storage["logs"] = logs_storage

        # Get first page (newest 5)
        response = client.get("/api/logs?limit=5")
        assert response.status_code == 200
        body = json.loads(response.data)
        page1 = body["logs"]
        assert len(page1) == 5
        # Newest timestamps first
        assert page1[0]["timestamp"] == 90.0
        assert page1[4]["timestamp"] == 50.0  # 5th from top
        cursor = body["next_cursor"]
        assert cursor == 50.0

        # Get second page using start_after
        response = client.get(f"/api/logs?limit=5&start_after={cursor}")
        assert response.status_code == 200
        body = json.loads(response.data)
        page2 = body["logs"]
        assert len(page2) == 5
        assert page2[0]["timestamp"] == 40.0
        assert page2[4]["timestamp"] == 0.0
        assert body["next_cursor"] is None  # no more pages

    def test_logs_invalid_limit(self, client, mock_firestore):
        """limit > 100 should be capped at 100."""
        logs_storage = {}
        for i in range(150):
            logs_storage[f"log_{i}"] = {
                "user_id": "test_user",
                "timestamp": float(i),
                "method": "FACE",
                "similarity": 0.9,
                "confidence": "HIGH",
                "image_url": f"http://example.com/{i}.jpg",
            }
        mock_firestore._storage["logs"] = logs_storage

        response = client.get("/api/logs?limit=200")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert len(body["logs"]) == 100

    def test_logs_descending_order(self, client, mock_firestore):
        """Logs should be returned in descending timestamp order (newest first)."""
        mock_firestore._storage["logs"] = {
            "log_old": {
                "user_id": "user1", "timestamp": 1000.0, "method": "FACE",
                "similarity": 0.80, "confidence": "MEDIUM-HIGH",
                "image_url": "http://example.com/old.jpg",
            },
            "log_mid": {
                "user_id": "user1", "timestamp": 3000.0, "method": "FACE",
                "similarity": 0.90, "confidence": "HIGH",
                "image_url": "http://example.com/mid.jpg",
            },
            "log_new": {
                "user_id": "user1", "timestamp": 5000.0, "method": "PIN",
                "success": True, "image_url": None,
            },
        }

        response = client.get("/api/logs")
        assert response.status_code == 200
        body = json.loads(response.data)
        logs = body["logs"]
        assert len(logs) == 3
        # Newest first
        assert logs[0]["timestamp"] == 5000.0
        assert logs[1]["timestamp"] == 3000.0
        assert logs[2]["timestamp"] == 1000.0
