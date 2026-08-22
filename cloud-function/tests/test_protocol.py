"""Protocol-v2 and cloud-route hardening regression tests.

All service boundaries are injected or patched; these tests do not contact GCP.
"""

import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from app import create_app
from app.encryption import aes_gcm_encrypt
from app.protocol import (
    ProtocolError,
    canonical_query_string,
    canonical_string,
    canonical_time_request,
    canonical_time_response,
    parse_device_credentials,
    sign_request,
    sign_time_request,
    sign_time_response,
)
# Reuse the dict-backed service fixtures from the route suite without making
# this file depend on a live Firebase project.
from tests.test_routes import (  # noqa: F401
    app,
    client,
    encrypted_jpeg,
    mock_bucket,
    mock_face_engine,
    mock_face_embedding,
    mock_firestore,
    sample_plaintext_jpeg,
    test_key,
)


HMAC_KEY = bytes.fromhex("22" * 32)


def _headers(body, *, device_id="cam-1", query="", nonce="ab" * 16):
    timestamp = str(int(time.time()))
    return {
        "X-Protocol-Version": "2",
        "X-Device-ID": device_id,
        "X-Timestamp": timestamp,
        "X-Request-Nonce": nonce,
        "X-Request-Signature": sign_request(
            HMAC_KEY,
            "POST",
            "/api/unlock",
            canonical_query_string(query),
            device_id,
            timestamp,
            nonce,
            body,
        ),
    }


def _configure_v2(app, user_ids=("alice",)):
    app.config["DEVICE_CREDENTIALS"] = parse_device_credentials(
        {
            "cam-1": {
                "hmac_key_hex": HMAC_KEY.hex(),
                "enabled": True,
                "allowed_user_ids": list(user_ids),
            }
        }
    )
    app.config["STRICT_IMAGE_VALIDATION"] = False


def test_protocol_primitives_are_canonical_and_strict():
    assert (
        canonical_query_string("b=2&a=hello%20world&a=")
        == "a=&a=hello+world&b=2"
    )
    assert canonical_string(
        "post", "/api/unlock", "", "cam-1", "10", "ab" * 16, "body"
    ).count("\n") == 7
    with pytest.raises(ProtocolError):
        sign_request(
            HMAC_KEY,
            "POST",
            "/api/unlock",
            "",
            "cam-1",
            "10",
            "AB" * 16,
            b"",
        )


def test_device_credentials_require_enabled_allow_list():
    parsed = parse_device_credentials(
        {
            "cam-1": {
                "hmac_key_hex": HMAC_KEY.hex(),
                "enabled": True,
                "allowed_user_ids": ["alice"],
            }
        }
    )
    assert parsed["cam-1"]["key"] == HMAC_KEY
    assert parsed["cam-1"]["allowed_user_ids"] == frozenset({"alice"})
    with pytest.raises(ValueError):
        parse_device_credentials(
            {
                "cam-1": {
                    "hmac_key_hex": HMAC_KEY.hex(),
                    "enabled": True,
                    "allowed_user_ids": ["*"],
                }
            }
        )


def test_device_time_challenge_is_clock_independent_and_domain_separated():
    nonce = "31" * 16
    request_message = canonical_time_request("cam-1", nonce)
    response_message = canonical_time_response("cam-1", nonce, 1780000000)

    assert request_message == "SAHL-TIME-V1\nGET\n/api/device_time\ncam-1\n" + nonce
    assert response_message.endswith("\n1780000000")
    assert sign_time_request(HMAC_KEY, "cam-1", nonce) != sign_time_response(
        HMAC_KEY, "cam-1", nonce, 1780000000
    )


def test_device_time_endpoint_authenticates_request_and_response(app, client):
    _configure_v2(app)
    nonce = "42" * 16
    with patch("app.routes.time.time", return_value=1780000000):
        response = client.get(
            "/api/device_time",
            headers={
                "X-Time-Protocol-Version": "1",
                "X-Device-ID": "cam-1",
                "X-Time-Nonce": nonce,
                "X-Time-Signature": sign_time_request(HMAC_KEY, "cam-1", nonce),
            },
        )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Time-Nonce"] == nonce
    assert response.headers["X-Server-Time"] == "1780000000"
    assert response.headers["X-Time-Signature"] == sign_time_response(
        HMAC_KEY, "cam-1", nonce, 1780000000
    )


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {
            "X-Time-Protocol-Version": "1",
            "X-Device-ID": "cam-1",
            "X-Time-Nonce": "42" * 16,
            "X-Time-Signature": "00" * 32,
        },
        {
            "X-Time-Protocol-Version": "1",
            "X-Device-ID": "unknown",
            "X-Time-Nonce": "42" * 16,
            "X-Time-Signature": "00" * 32,
        },
    ],
)
def test_device_time_endpoint_fails_closed(app, client, headers):
    _configure_v2(app)
    response = client.get("/api/device_time", headers=headers)
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid time request"}


def test_device_time_endpoint_rejects_query_and_body(app, client):
    _configure_v2(app)
    nonce = "42" * 16
    headers = {
        "X-Time-Protocol-Version": "1",
        "X-Device-ID": "cam-1",
        "X-Time-Nonce": nonce,
        "X-Time-Signature": sign_time_request(HMAC_KEY, "cam-1", nonce),
    }
    assert client.get("/api/device_time?extra=1", headers=headers).status_code == 400
    assert client.get("/api/device_time", headers=headers, data=b"x").status_code == 400


def test_v2_high_unlock_requires_signature_and_marks_response(
    app, client, mock_firestore, mock_face_embedding, encrypted_jpeg
):
    _configure_v2(app)
    mock_firestore._storage.setdefault("users", {})["alice"] = {
        "image1": mock_face_embedding,
    }
    with patch("app.routes.reserve_replay", return_value=True), patch(
        "app.routes._log_event", return_value=None
    ), patch("app.routes.send_unlock_notification"):
        response = client.post(
            "/api/unlock",
            data=encrypted_jpeg,
            headers=_headers(encrypted_jpeg),
        )
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "UNLOCK"
    assert body["protocol_version"] == 2
    assert body["legacy"] is False
    assert response.headers["X-Protocol-Version"] == "2"


def test_v2_missing_or_partial_headers_never_fall_back_to_v1(
    app, client, encrypted_jpeg
):
    _configure_v2(app)
    response = client.post(
        "/api/unlock",
        data=encrypted_jpeg,
        headers={"X-Protocol-Version": "2"},
    )
    assert response.status_code == 401
    assert response.get_json()["protocol_version"] == 2

    response = client.post(
        "/api/unlock",
        data=encrypted_jpeg,
        headers={"X-Device-ID": "cam-1"},
    )
    assert response.status_code == 401
    assert response.get_json()["protocol_version"] == 2

    response = client.post(
        "/api/unlock",
        data=encrypted_jpeg,
        headers={"X-Protocol-Version": "9"},
    )
    assert response.status_code == 400


def test_v2_replay_duplicate_and_store_failure_are_fail_closed(
    app, client, mock_firestore, mock_face_embedding, encrypted_jpeg
):
    _configure_v2(app)
    mock_firestore._storage.setdefault("users", {})["alice"] = {
        "image1": mock_face_embedding,
    }
    with patch("app.routes.reserve_replay", return_value=False):
        duplicate = client.post(
            "/api/unlock",
            data=encrypted_jpeg,
            headers=_headers(encrypted_jpeg, nonce="cd" * 16),
        )
    assert duplicate.status_code == 409
    assert duplicate.get_json()["protocol_version"] == 2

    from app.protocol import ReplayStoreError

    with patch(
        "app.routes.reserve_replay", side_effect=ReplayStoreError("backend")
    ), patch("app.routes._log_event") as log_event:
        failed = client.post(
            "/api/unlock",
            data=encrypted_jpeg,
            headers=_headers(encrypted_jpeg, nonce="ef" * 16),
        )
    assert failed.status_code == 503
    assert failed.get_json()["protocol_version"] == 2
    log_event.assert_not_called()


def test_v1_compatibility_response_is_explicitly_legacy(
    client, mock_firestore, mock_face_embedding, encrypted_jpeg
):
    mock_firestore._storage.setdefault("users", {})["alice"] = {
        "image1": mock_face_embedding,
    }
    with patch("app.routes._log_event", return_value=None), patch(
        "app.routes.send_unlock_notification"
    ):
        response = client.post(
            "/api/unlock",
            data=encrypted_jpeg,
            headers={"X-Protocol-Version": "1", "X-Legacy-Protocol": "1"},
        )
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "UNLOCK"
    assert body["protocol_version"] == 1
    assert body["legacy"] is True
    assert response.headers["X-Legacy-Protocol"] == "1"


def test_v2_medium_match_is_denied_without_learning(
    app, client, mock_firestore, mock_face_embedding, test_key
):
    _configure_v2(app)
    reference = np.asarray(mock_face_embedding, dtype=np.float64)
    random = np.random.default_rng(123).normal(size=512)
    random -= np.dot(random, reference) * reference
    random /= np.linalg.norm(random)
    medium = 0.65 * reference + np.sqrt(1 - 0.65**2) * random
    mock_firestore._storage.setdefault("users", {})["alice"] = {
        "image1": medium.tolist(),
    }
    encrypted = aes_gcm_encrypt(b"not-an-image", test_key)
    with patch("app.routes.reserve_replay", return_value=True), patch(
        "app.routes.store_adaptive_embedding"
    ) as store, patch("app.routes.prune_adaptive_embeddings") as prune, patch(
        "app.routes.send_unlock_notification"
    ) as send:
        response = client.post(
            "/api/unlock",
            data=encrypted,
            headers=_headers(encrypted, nonce="12" * 16),
        )
    assert response.status_code == 200
    assert response.get_json()["status"] != "UNLOCK"
    store.assert_not_called()
    prune.assert_not_called()
    send.assert_not_called()


def test_admin_bearer_matrix_does_not_use_user_id_as_authorization(
    mock_face_engine, mock_firestore, mock_bucket, test_key
):
    production_app = create_app(
        mock_face_engine,
        mock_firestore,
        mock_bucket,
        test_key,
        testing=False,
        auth_bypass=False,
    )
    production_client = production_app.test_client()
    request_data = {"user_id": "alice"}
    response = production_client.post(
        "/api/register", data=request_data, content_type="multipart/form-data"
    )
    assert response.status_code == 401

    with patch("firebase_admin.auth.verify_id_token", return_value={"admin": False}):
        response = production_client.post(
            "/api/register",
            data=request_data,
            content_type="multipart/form-data",
            headers={"Authorization": "Bearer token"},
        )
    assert response.status_code == 403

    with patch("firebase_admin.auth.verify_id_token", return_value={"admin": True}):
        response = production_client.post(
            "/api/register",
            data=request_data,
            content_type="multipart/form-data",
            headers={"Authorization": "Bearer token"},
        )
    assert response.status_code == 400


def test_set_pin_requires_existing_user_when_enabled(
    app, client, mock_firestore, test_key, monkeypatch
):
    app.config["REQUIRE_EXISTING_USER_FOR_PIN"] = True
    encrypted = aes_gcm_encrypt(b"123456", test_key)

    users = MagicMock()
    missing_snapshot = MagicMock(exists=False)
    present_snapshot = MagicMock(exists=True)
    users.document.return_value.get.return_value = missing_snapshot
    original_collection = mock_firestore.collection
    monkeypatch.setattr(
        mock_firestore,
        "collection",
        lambda name: users if name == "users" else original_collection(name),
    )
    response = client.post("/api/set_pin?user_id=missing", data=encrypted)
    assert response.status_code == 404
    users.document.return_value.get.return_value = present_snapshot
    response = client.post("/api/set_pin?user_id=present", data=encrypted)
    assert response.status_code == 200


def test_datetime_log_cursor_is_json_safe_and_stable(app, client, mock_firestore):
    first = datetime(2026, 1, 2, tzinfo=timezone.utc)
    second = datetime(2026, 1, 1, tzinfo=timezone.utc)
    mock_firestore._storage["logs"] = {
        "new": {
            "user_id": "alice",
            "timestamp": first,
            "method": "PIN",
            "success": True,
        },
        "old": {
            "user_id": "alice",
            "timestamp": second,
            "method": "PIN",
            "success": False,
        },
    }
    response = client.get("/api/logs?limit=1")
    assert response.status_code == 200
    body = response.get_json()
    assert body["logs"][0]["timestamp"].endswith("Z")
    assert body["next_cursor"]["log_id"] == "new"
    response = client.get(
        "/api/logs",
        query_string={"limit": "1", "cursor": json.dumps(body["next_cursor"])},
    )
    assert response.status_code == 200
    assert response.get_json()["logs"][0]["log_id"] == "old"


def test_unlock_body_limit_is_controlled(app, client, encrypted_jpeg):
    app.config["MAX_ENCRYPTED_UNLOCK_BYTES"] = len(encrypted_jpeg) - 1
    response = client.post("/api/unlock", data=encrypted_jpeg)
    assert response.status_code == 413
    assert response.get_json() == {"error": "request too large"}


def test_delete_cascades_devices_logs_and_opaque_gcs_objects(
    client, mock_firestore, mock_bucket
):
    mock_firestore._storage["users"] = {
        "alice": {"_sc_devices": {"device": {"token": "t", "is_active": True}}}
    }
    mock_firestore._storage["pins"] = {"alice": {"hash": "old"}}
    mock_firestore._storage["logs"] = {
        "log-1": {
            "user_id": "alice",
            "timestamp": 10.0,
            "image_object": "logs/alice/10-deadbeef.jpg",
        }
    }
    response = client.delete("/api/user?user_id=alice")
    assert response.status_code == 200
    assert "alice" not in mock_firestore._storage["users"]
    assert "alice" not in mock_firestore._storage["pins"]
    assert "log-1" not in mock_firestore._storage["logs"]
    mock_bucket.blob.assert_any_call("logs/alice/10-deadbeef.jpg")


def test_invalid_stored_embedding_cannot_false_unlock(
    app, client, mock_firestore, mock_face_embedding, encrypted_jpeg
):
    mock_firestore._storage.setdefault("users", {})["alice"] = {
        "image1": [float("nan")] * 512,
        "image2": [0.0] * 512,
    }
    with patch("app.routes.send_unlock_notification") as send:
        response = client.post("/api/unlock", data=encrypted_jpeg)
    assert response.status_code == 200
    assert response.get_json()["status"] == "NO_MATCH"
    send.assert_not_called()
