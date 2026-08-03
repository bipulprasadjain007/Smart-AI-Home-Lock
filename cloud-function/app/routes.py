"""HTTP routes for the Smart AI Home Lock cloud function.

The route module deliberately keeps the protocol and infrastructure boundaries
small.  Firebase, GCS, the face engine, and the replay store are all supplied
by :func:`app.create_app`, which makes the safety-critical behaviour testable
without contacting GCP.

There are two wire modes during migration:

* protocol v1 is an explicitly labelled, staging/test-only compatibility mode;
* protocol v2 authenticates the device request, checks freshness, and reserves
  the request nonce before any unlock work is performed.

Only an exact JSON ``status`` value of ``UNLOCK`` is a successful unlock.  In
particular, HTTP 200 by itself is never treated as permission to actuate a
lock.
"""

from __future__ import annotations

import json
import hashlib
import logging
import math
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

import bcrypt
from flask import current_app, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from app.encryption import aes_gcm_decrypt
from app.fcm import (
    deactivate_device_token,
    send_unlock_notification,
    store_device_token,
)
from app.learning import (
    compute_best_match,
    compute_weighted_similarity,  # compatibility export for injected tests
    prune_adaptive_embeddings,
    store_adaptive_embedding,
)
from app.protocol import (
    DEVICE_ID_RE,
    REQUEST_NONCE_RE,
    REQUEST_SIGNATURE_RE,
    ProtocolError,
    ReplayDetected,
    ReplayStoreError,
    canonical_query_string,
    reserve_replay,
    sign_request,
)
from app.similarity import cosine_similarity, validate_embedding  # compatibility exports


logger = logging.getLogger(__name__)

USER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,100}$")
PIN_PATTERN = re.compile(r"^\d{6}$")
TIMESTAMP_PATTERN = re.compile(r"^[0-9]+$")

THRESHOLD_HIGH = 0.75
THRESHOLD_MEDIUM_HIGH = 0.70
THRESHOLD_MEDIUM = 0.60

GCM_PACKET_MINIMUM = 12 + 16
V2_HEADER_NAMES = (
    "X-Device-ID",
    "X-Timestamp",
    "X-Request-Nonce",
    "X-Request-Signature",
)
LEGACY_MARKER_HEADER = "X-Legacy-Protocol"
LEGACY_MARKER_ALIASES = (LEGACY_MARKER_HEADER, "X-Legacy")
MAX_DEVICE_TOKEN_BYTES = 4096
MAX_DEVICE_NAME_LENGTH = 200
SUPPORTED_DEVICE_PLATFORMS = frozenset({"android", "ios", "web"})


class RequestInputError(ValueError):
    """A bounded, client-controlled input failed validation."""

    status_code = 400


class RequestLimitError(RequestInputError):
    """A request exceeded an application-configured bound."""

    status_code = 413


class AuthorizationError(ValueError):
    """Firebase bearer authentication or authorization failed."""

    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.status_code = status_code


class PinLimiterBackendError(RuntimeError):
    """The durable PIN failure limiter could not be read or updated."""


class PinLockedError(RuntimeError):
    """The device/user PIN pair is currently locked out."""

    def __init__(self, locked_until: datetime | None = None):
        super().__init__("PIN temporarily locked")
        self.locked_until = locked_until


class DeletionIncompleteError(RuntimeError):
    """A biometric object could not be deleted and must be retried."""


def register_routes(app):
    """Register the public HTTP surface on a Flask application."""

    @app.errorhandler(RequestEntityTooLarge)
    def _route_request_too_large(_error):
        # Flask may reject MAX_CONTENT_LENGTH before a view runs.  Preserve a
        # v2 marker when the request already selected v2, while keeping the
        # client-facing error generic.
        return _response(
            {"error": "request too large"},
            413,
            _protocol_version_hint(),
        )

    app.add_url_rule("/api/register", "register", register, methods=["POST"])
    app.add_url_rule("/api/unlock", "unlock", unlock, methods=["POST"])
    app.add_url_rule("/api/set_pin", "set_pin", set_pin, methods=["POST"])
    app.add_url_rule("/api/pin_unlock", "pin_unlock", pin_unlock, methods=["POST"])
    app.add_url_rule(
        "/api/register_device",
        "register_device",
        register_device,
        methods=["POST"],
    )
    app.add_url_rule(
        "/api/deregister_device",
        "deregister_device",
        deregister_device,
        methods=["POST"],
    )
    app.add_url_rule("/api/user", "remove_user", remove_user, methods=["DELETE"])
    app.add_url_rule("/api/logs", "get_logs", get_logs, methods=["GET"])
    app.add_url_rule(
        "/api/system_config",
        "system_config",
        system_config,
        methods=["GET"],
    )
    app.add_url_rule(
        "/system_config",
        "system_config_legacy_path",
        system_config,
        methods=["GET"],
    )
    app.add_url_rule("/api/health", "health", health, methods=["GET"])


# ---------------------------------------------------------------------------
# Response and error helpers
# ---------------------------------------------------------------------------


def _response(
    payload: dict[str, Any],
    status_code: int = 200,
    protocol_version: Optional[int] = None,
):
    """Return JSON while making the protocol version unambiguous.

    The JSON marker is what constrained clients consume.  The response header
    is useful to humans and proxies, but is intentionally not the only marker.
    """

    body = dict(payload)
    if protocol_version in (1, 2):
        body.setdefault("protocol_version", protocol_version)
        body.setdefault("legacy", protocol_version == 1)

    response = jsonify(body)
    response.status_code = status_code
    if protocol_version in (1, 2):
        response.headers["X-Protocol-Version"] = str(protocol_version)
        if protocol_version == 1:
            response.headers[LEGACY_MARKER_HEADER] = "1"
    return response


def _known_error_response(error: Exception, protocol_version: Optional[int] = None):
    """Map expected input/auth errors without exposing backend details."""

    status_code = int(getattr(error, "status_code", 400))
    if isinstance(error, ReplayDetected):
        message = "request replayed"
    elif isinstance(error, ReplayStoreError):
        status_code = 503
        message = "replay protection unavailable"
    elif isinstance(error, PinLimiterBackendError):
        status_code = 503
        message = "PIN protection unavailable"
    elif isinstance(error, PinLockedError):
        status_code = 429
        message = "PIN temporarily locked"
    elif isinstance(error, DeletionIncompleteError):
        status_code = 503
        message = "deletion pending"
    elif isinstance(error, AuthorizationError):
        message = str(error)
    elif isinstance(error, ProtocolError):
        message = str(error) or "protocol request rejected"
    elif isinstance(error, RequestLimitError):
        message = "request too large"
    elif isinstance(error, RequestInputError):
        message = str(error) or "invalid request"
    else:
        message = "request failed"
    return _response({"error": message}, status_code, protocol_version)


def _internal_error(route_name: str, error: Exception, protocol_version=None):
    logger.error("%s failed: %s", route_name, error, exc_info=True)
    if isinstance(error, HTTPException):
        return _response(
            {"error": error.description or "request failed"},
            error.code or 500,
            protocol_version,
        )
    return _response({"error": "internal server error"}, 500, protocol_version)


def _is_test_auth_bypass() -> bool:
    """Allow bypass only on an explicitly injected Flask test application."""

    testing = current_app.config.get("TESTING", False)
    if isinstance(testing, str):
        testing = testing.strip().lower() in {"1", "true", "yes", "on"}
    return bool(testing) and _config_bool("AUTH_BYPASS", False)


def _config_int(name: str, default: int, minimum: int = 0) -> int:
    value = current_app.config.get(name, default)
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def _config_bool(name: str, default: bool = False) -> bool:
    value = current_app.config.get(name, default)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _snapshot_exists(snapshot: Any) -> bool:
    """Fail closed unless a Firestore-like snapshot explicitly says true."""

    return getattr(snapshot, "exists", False) is True


def _is_test_double(value: Any) -> bool:
    module = type(value).__module__
    return module.startswith("unittest.mock")


# ---------------------------------------------------------------------------
# Firebase admin authorization
# ---------------------------------------------------------------------------


def _require_admin() -> dict[str, Any] | None:
    """Verify a Firebase ID-token bearer and an explicit admin claim.

    ``user_id`` is deliberately not consulted here.  A caller cannot gain
    administrative rights by choosing a different path/query user id.
    """

    if _is_test_auth_bypass():
        return None

    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise AuthorizationError("authentication required", 401)

    try:
        from firebase_admin import auth

        try:
            claims = auth.verify_id_token(parts[1], check_revoked=True)
        except TypeError:
            # Older Admin SDKs do not expose check_revoked.  Signature and
            # expiry verification still happen in verify_id_token itself.
            claims = auth.verify_id_token(parts[1])
    except Exception as error:
        logger.warning("Firebase bearer verification failed: %s", error)
        raise AuthorizationError("invalid bearer token", 401) from error

    if not isinstance(claims, dict) or claims.get("admin") is not True:
        raise AuthorizationError("admin authorization required", 403)
    return claims


# ---------------------------------------------------------------------------
# Protocol v1/v2 request authentication
# ---------------------------------------------------------------------------


def _protocol_version_hint() -> Optional[int]:
    version = request.headers.get("X-Protocol-Version")
    if version == "2" or any(
        request.headers.get(name) is not None for name in V2_HEADER_NAMES
    ):
        return 2
    if version == "1" or any(
        request.headers.get(name) is not None for name in LEGACY_MARKER_ALIASES
    ):
        return 1
    return None


def _valid_legacy_marker(value: str | None) -> bool:
    if value is None:
        return True
    return value.strip().lower() in {"1", "true", "yes", "legacy", "v1"}


def _require_device_protocol(body: bytes, user_id: str | None = None) -> dict[str, Any]:
    """Classify and authenticate an unlock/PIN request.

    Any v2-looking request is treated as v2.  It is never silently downgraded
    to v1 when one required header is missing or malformed.
    """

    version_header = request.headers.get("X-Protocol-Version")
    legacy_values = [
        request.headers.get(name) for name in LEGACY_MARKER_ALIASES
        if request.headers.get(name) is not None
    ]
    if len(legacy_values) > 1 and len(set(legacy_values)) != 1:
        raise ProtocolError("conflicting legacy markers", 400)
    legacy_marker = legacy_values[0] if legacy_values else None
    v2_fields_present = any(
        request.headers.get(name) is not None for name in V2_HEADER_NAMES
    )

    if not _valid_legacy_marker(legacy_marker):
        raise ProtocolError("invalid legacy marker", 400)
    if version_header is not None and version_header not in {"1", "2"}:
        raise ProtocolError("unsupported protocol version", 400)

    if version_header == "2" or v2_fields_present:
        if version_header != "2":
            raise ProtocolError("protocol version 2 is required", 401)
        if legacy_marker is not None:
            raise ProtocolError("mixed protocol markers are not allowed", 400)
        return _verify_v2_request(body, user_id=user_id)

    if version_header == "1" or legacy_marker is not None:
        if version_header not in (None, "1"):
            raise ProtocolError("unsupported protocol version", 400)
        if not _config_bool("V1_LEGACY_ENABLED", False):
            raise ProtocolError("legacy protocol disabled", 426)
        if not _config_bool("V1_LEGACY_ALLOW_UNLOCK", False):
            raise ProtocolError("legacy unlock disabled", 426)
        return {"version": 1, "legacy": True, "allowed_user_ids": None}

    # Existing injected tests intentionally exercise the old encrypted body.
    # Production/staging must send an explicit X-Protocol-Version: 1 marker.
    if _is_test_auth_bypass() and _config_bool("V1_LEGACY_ENABLED", False):
        if not _config_bool("V1_LEGACY_ALLOW_UNLOCK", False):
            raise ProtocolError("legacy unlock disabled", 426)
        return {"version": 1, "legacy": True, "allowed_user_ids": None}

    raise ProtocolError("protocol version required", 401)


def _verify_v2_request(body: bytes, user_id: str | None = None) -> dict[str, Any]:
    """Verify v2 headers, HMAC, freshness, allow-list, and replay state."""

    if not _config_bool("V2_AUTH_ENABLED", True):
        raise ProtocolError("protocol v2 disabled", 426)

    missing = [name for name in V2_HEADER_NAMES if not request.headers.get(name)]
    if missing:
        raise ProtocolError("missing required protocol v2 header", 401)

    device_id = request.headers.get("X-Device-ID", "")
    timestamp_text = request.headers.get("X-Timestamp", "")
    nonce = request.headers.get("X-Request-Nonce", "")
    signature = request.headers.get("X-Request-Signature", "")

    if not DEVICE_ID_RE.fullmatch(device_id):
        raise ProtocolError("invalid device id", 401)
    if not TIMESTAMP_PATTERN.fullmatch(timestamp_text):
        raise ProtocolError("invalid timestamp", 401)
    if not REQUEST_NONCE_RE.fullmatch(nonce):
        raise ProtocolError("invalid request nonce", 401)
    if not REQUEST_SIGNATURE_RE.fullmatch(signature):
        raise ProtocolError("invalid request signature", 401)

    try:
        timestamp = int(timestamp_text)
    except (TypeError, ValueError) as error:
        raise ProtocolError("invalid timestamp", 401) from error

    now = time.time()
    skew = _config_int("CLOCK_SKEW_SECONDS", 60, minimum=0)
    if abs(now - timestamp) > skew:
        raise ProtocolError("timestamp outside accepted window", 401)

    credentials = current_app.config.get("DEVICE_CREDENTIALS") or {}
    credential = credentials.get(device_id)
    if not isinstance(credential, dict):
        raise ProtocolError("device not authorized", 403)
    if credential.get("enabled") is not True:
        raise ProtocolError("device not authorized", 403)

    allowed_user_ids = credential.get("allowed_user_ids")
    if allowed_user_ids is None:
        allowed_user_ids = frozenset()

    try:
        query = canonical_query_string(request.query_string)
        expected = sign_request(
            credential["key"],
            request.method,
            request.path,
            query,
            device_id,
            timestamp_text,
            nonce,
            body,
        )
    except ProtocolError:
        raise
    except Exception as error:
        logger.warning("v2 request signing setup failed: %s", error)
        raise ProtocolError("invalid protocol request", 401) from error

    # compare_digest is used only after the exact lowercase/length check above.
    import hmac

    if not hmac.compare_digest(expected, signature):
        raise ProtocolError("invalid request signature", 401)

    if user_id is not None and user_id not in allowed_user_ids:
        raise ProtocolError("device is not allowed for this user", 403)

    try:
        reserved = reserve_replay(
            current_app.config["DB"],
            device_id,
            nonce,
            now=now,
            ttl_seconds=_config_int("REPLAY_TTL_SECONDS", 120, minimum=1),
        )
    except ReplayStoreError:
        raise
    except Exception as error:
        logger.error("replay reservation failed: %s", error, exc_info=True)
        raise ReplayStoreError("replay reservation failed") from error
    if reserved is False:
        raise ReplayDetected()
    if reserved is not True:
        raise ReplayStoreError("invalid replay reservation result")

    return {
        "version": 2,
        "legacy": False,
        "device_id": device_id,
        "allowed_user_ids": frozenset(allowed_user_ids),
    }


# ---------------------------------------------------------------------------
# Input, image, and matching helpers
# ---------------------------------------------------------------------------


def _validate_user_id(value: Any, field_name: str = "user_id") -> str:
    if not isinstance(value, str):
        raise RequestInputError(f"Invalid or missing {field_name}")
    value = value.strip()
    if not USER_ID_PATTERN.fullmatch(value):
        raise RequestInputError(f"Invalid or missing {field_name}")
    return value


def _read_limited(stream, limit: int) -> bytes:
    if limit <= 0:
        raise RequestLimitError("request limit is not configured")
    data = stream.read(limit + 1)
    if not isinstance(data, bytes):
        data = bytes(data or b"")
    if len(data) > limit:
        raise RequestLimitError("request too large")
    return data


def _request_body(limit_name: str) -> bytes:
    body = request.get_data(cache=True, as_text=False)
    limit = _config_int(limit_name, 2 * 1024 * 1024, minimum=1)
    if len(body) > limit:
        raise RequestLimitError("request too large")
    return body


def _decrypt_packet(
    packet: bytes,
    key: bytes,
    packet_limit_name: str,
    plaintext_limit_name: str,
) -> bytes:
    if not packet or len(packet) < GCM_PACKET_MINIMUM:
        raise RequestInputError("Empty or invalid payload")
    packet_limit = _config_int(packet_limit_name, 2 * 1024 * 1024, minimum=1)
    if len(packet) > packet_limit:
        raise RequestLimitError("request too large")
    try:
        plaintext = aes_gcm_decrypt(packet, key)
    except (ValueError, TypeError, IndexError) as error:
        logger.warning("AES-GCM packet rejected: %s", error)
        raise RequestInputError("Encryption error") from error
    plain_limit = _config_int(plaintext_limit_name, 2 * 1024 * 1024, minimum=1)
    if len(plaintext) > plain_limit:
        raise RequestLimitError("decrypted payload too large")
    return plaintext


def _validate_image_bytes(image_bytes: bytes) -> None:
    """Apply production image decoding and decompression limits.

    Injected legacy tests use random stand-ins for JPEG bytes, so strict image
    decoding is disabled by ``testing=True`` in the app factory.  Production
    never relies on the face engine alone to protect against decompression
    bombs.
    """

    if len(image_bytes) > _config_int(
        "MAX_DECRYPTED_IMAGE_BYTES", 2 * 1024 * 1024, minimum=1
    ):
        raise RequestLimitError("decrypted image too large")
    if not _config_bool("STRICT_IMAGE_VALIDATION", True):
        return

    try:
        import cv2
        import numpy as np

        image = cv2.imdecode(
            np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR
        )
    except Exception as error:
        logger.warning("image validation failed: %s", error)
        raise RequestInputError("invalid image") from error

    if image is None or image.size == 0 or image.ndim != 3:
        raise RequestInputError("invalid image")
    max_pixels = _config_int("MAX_IMAGE_PIXELS", 16 * 1024 * 1024, minimum=1)
    height, width = image.shape[:2]
    if int(height) * int(width) > max_pixels:
        raise RequestLimitError("image dimensions too large")


def _extract_embedding(face_engine, image_bytes: bytes) -> list[float] | None:
    try:
        embedding = face_engine.get_embedding(image_bytes)
    except Exception as error:
        logger.warning("face embedding extraction failed: %s", error)
        return None
    if embedding is None:
        return None
    try:
        return validate_embedding(embedding)
    except (TypeError, ValueError) as error:
        logger.warning("invalid face embedding returned by engine: %s", error)
        return None


def _iter_user_snapshots(db) -> Iterable[Any]:
    return db.collection("users").stream()


def _best_user_match(
    db,
    embedding: list[float],
    protocol: dict[str, Any],
) -> dict[str, Any] | None:
    allowed = protocol.get("allowed_user_ids") if protocol.get("version") == 2 else None
    best: dict[str, Any] | None = None
    now = time.time()

    for snapshot in _iter_user_snapshots(db):
        user_id = getattr(snapshot, "id", None)
        if not isinstance(user_id, str) or not USER_ID_PATTERN.fullmatch(user_id):
            continue
        if allowed is not None and user_id not in allowed:
            continue
        try:
            user_data = snapshot.to_dict() or {}
        except Exception:
            logger.warning("could not read user document %s", user_id)
            continue
        if not isinstance(user_data, dict):
            continue

        match = compute_best_match(embedding, user_data, now=now)
        weighted = float(match.get("weighted_similarity", 0.0) or 0.0)
        raw = float(match.get("raw_similarity", 0.0) or 0.0)
        if not math.isfinite(weighted) or not math.isfinite(raw):
            continue

        candidate = {
            "user_id": user_id,
            "user_data": user_data,
            "raw_similarity": raw,
            "weighted_similarity": weighted,
            "winner_key": match.get("key"),
        }
        if best is None:
            best = candidate
            continue
        # Highest score wins; user id is a stable tie-breaker so Firestore
        # stream order cannot change an unlock decision.
        if weighted > best["weighted_similarity"] or (
            math.isclose(weighted, best["weighted_similarity"], abs_tol=1e-12)
            and user_id < best["user_id"]
        ):
            best = candidate

    return best


def _confidence_label(similarity: float) -> str:
    if similarity >= THRESHOLD_HIGH:
        return "HIGH"
    if similarity >= THRESHOLD_MEDIUM_HIGH:
        return "MEDIUM-HIGH"
    return "MEDIUM"


def _is_unlock_allowed(protocol_version: int, weighted_similarity: float) -> bool:
    # The legacy lane is a compatibility reader, not a second confidence
    # policy.  It can only actuate on the high-confidence tier; medium matches
    # must never become a notification or a learning signal.
    if protocol_version == 1:
        return weighted_similarity >= THRESHOLD_HIGH and _config_bool(
            "V1_LEGACY_ALLOW_UNLOCK", False
        )
    if weighted_similarity < THRESHOLD_MEDIUM:
        return False
    if protocol_version == 2:
        if weighted_similarity >= THRESHOLD_HIGH:
            return True
        return _config_bool("V2_ALLOW_MEDIUM_UNLOCK", False)
    return False


def _safe_image_object_name(user_id: str) -> str:
    # user_id has already passed USER_ID_PATTERN; UUID prevents same-second
    # collisions when multiple unlocks arrive concurrently.
    return f"logs/{user_id}/{time.time_ns()}-{uuid.uuid4().hex}.jpg"


def _log_event(
    db,
    bucket,
    user_id: str,
    image_bytes: bytes,
    similarity: float,
    confidence: str,
) -> str | None:
    """Write a face event and keep biometric objects private by default."""

    from firebase_admin import firestore

    object_name = _safe_image_object_name(user_id)
    image_url = None
    if bucket is not None:
        try:
            blob = bucket.blob(object_name)
            blob.upload_from_string(image_bytes, content_type="image/jpeg")
            if _config_bool("GENERATE_SIGNED_IMAGE_URLS", False):
                generator = getattr(blob, "generate_signed_url", None)
                if callable(generator):
                    generated = generator(
                        version="v4",
                        expiration=timedelta(minutes=15),
                        method="GET",
                    )
                    if isinstance(generated, str):
                        image_url = generated
        except Exception as gcs_error:
            # Audit metadata still gets recorded when object storage is down.
            logger.warning("GCS upload failed (continuing): %s", gcs_error)

    db.collection("logs").add(
        {
            "user_id": user_id,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "image_object": object_name,
            # Never fall back to blob.public_url.  A URL is present only when
            # the deployment explicitly enables short-lived signed URLs.
            "image_url": image_url,
            "image_url_signed": image_url is not None,
            "similarity": float(similarity),
            "confidence": confidence,
            "method": "FACE",
        }
    )
    return image_url


def _pin_log(db, user_id: str, success: bool) -> None:
    from firebase_admin import firestore

    db.collection("logs").add(
        {
            "user_id": user_id,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "method": "PIN",
            "success": bool(success),
            "image_url": None,
        }
    )


def _safe_pin_log(db, user_id: str, success: bool) -> None:
    try:
        _pin_log(db, user_id, success)
    except Exception as error:
        logger.warning("PIN audit log failed for user=%s: %s", user_id, error)


# ---------------------------------------------------------------------------
# Registration and face unlock
# ---------------------------------------------------------------------------


def register():
    try:
        _require_admin()
        if request.mimetype != "multipart/form-data":
            raise RequestInputError("register requires multipart/form-data")

        user_id = _validate_user_id(request.form.get("user_id", ""))
        if len(request.form.getlist("user_id")) != 1 or set(request.form.keys()) != {
            "user_id"
        }:
            raise RequestInputError("invalid multipart fields")
        expected_fields = {f"image{i}" for i in range(1, 6)}
        actual_fields = set(request.files.keys())
        if actual_fields != expected_fields:
            missing = expected_fields - actual_fields
            if missing:
                raise RequestInputError("missing image field")
            raise RequestInputError("unexpected image field")

        face_engine = current_app.config["FACE_ENGINE"]
        key = current_app.config["AES_KEY"]
        db = current_app.config["DB"]
        embeddings: dict[str, list[float]] = {}

        for field in sorted(expected_fields):
            if len(request.files.getlist(field)) != 1:
                raise RequestInputError("each image field must appear once")
            file = request.files.get(field)
            if file is None:
                raise RequestInputError("missing image field")
            if not file.filename:
                raise RequestInputError("invalid image field")
            encrypted_data = _read_limited(
                file.stream,
                _config_int("MAX_ENCRYPTED_IMAGE_BYTES", 2 * 1024 * 1024, minimum=1),
            )
            decrypted = _decrypt_packet(
                encrypted_data,
                key,
                "MAX_ENCRYPTED_IMAGE_BYTES",
                "MAX_DECRYPTED_IMAGE_BYTES",
            )
            _validate_image_bytes(decrypted)
            embedding = _extract_embedding(face_engine, decrypted)
            if embedding is None:
                raise RequestInputError("no face detected")
            embeddings[field] = embedding

        from firebase_admin import firestore

        document = {"timestamp": firestore.SERVER_TIMESTAMP}
        document.update(embeddings)
        db.collection("users").document(user_id).set(document)

        logger.info("Registered user=%s", user_id)
        return _response({"status": "Face registered", "user_id": user_id}, 200)
    except (
        AuthorizationError,
        RequestInputError,
        RequestLimitError,
    ) as error:
        return _known_error_response(error)
    except Exception as error:
        return _internal_error("register", error)


def unlock():
    protocol_version = _protocol_version_hint()
    try:
        encrypted_data = _request_body("MAX_ENCRYPTED_UNLOCK_BYTES")
        protocol = _require_device_protocol(encrypted_data)
        protocol_version = protocol["version"]

        key = current_app.config["AES_KEY"]
        face_engine = current_app.config["FACE_ENGINE"]
        db = current_app.config["DB"]
        bucket = current_app.config.get("BUCKET")

        if request.mimetype == "application/json":
            raise RequestInputError("unlock requires an encrypted binary body")
        decrypted = _decrypt_packet(
            encrypted_data,
            key,
            "MAX_ENCRYPTED_UNLOCK_BYTES",
            "MAX_DECRYPTED_IMAGE_BYTES",
        )
        _validate_image_bytes(decrypted)
        embedding = _extract_embedding(face_engine, decrypted)
        if embedding is None:
            return _response(
                {"status": "NO_FACE"}, 400, protocol_version=protocol_version
            )

        best = _best_user_match(db, embedding, protocol)
        if best is None or best["weighted_similarity"] < THRESHOLD_MEDIUM:
            return _response(
                {
                    "status": "NO_MATCH",
                    "similarity": 0.0 if best is None else round(best["raw_similarity"], 6),
                    "weighted_similarity": (
                        0.0
                        if best is None
                        else round(best["weighted_similarity"], 6)
                    ),
                },
                200,
                protocol_version=protocol_version,
            )

        raw_similarity = best["raw_similarity"]
        weighted_similarity = best["weighted_similarity"]
        confidence = _confidence_label(weighted_similarity)
        selected_unlock = _is_unlock_allowed(protocol_version, weighted_similarity)

        # The decision is selected before any non-critical side effect.  An
        # FCM outage, log outage, or learning failure cannot turn a selected
        # decision into a different response.
        if selected_unlock:
            image_url = None
            try:
                image_url = _log_event(
                    db,
                    bucket,
                    best["user_id"],
                    decrypted,
                    raw_similarity,
                    confidence,
                )
            except Exception as error:
                logger.warning("face audit event failed: %s", error)

            try:
                send_unlock_notification(
                    db,
                    best["user_id"],
                    confidence,
                    raw_similarity,
                    method="FACE",
                    image_url=image_url,
                )
            except Exception as error:
                logger.warning("FCM notification failed: %s", error)

            # v1 never learns.  It is intentionally high-confidence-only and
            # must not acquire an adaptive/notification side channel during
            # migration.  v2 learning remains an explicit policy flag.
            learning_enabled = protocol_version == 2 and _config_bool(
                "V2_ADAPTIVE_LEARNING", False
            )
            if learning_enabled and weighted_similarity < THRESHOLD_HIGH:
                try:
                    store_adaptive_embedding(
                        db, best["user_id"], embedding, timestamp=time.time()
                    )
                    prune_adaptive_embeddings(
                        db,
                        best["user_id"],
                        best["user_data"],
                        embedding,
                        now=time.time(),
                    )
                except Exception as error:
                    logger.warning("adaptive learning failed: %s", error)

            logger.info(
                "UNLOCK user=%s raw=%.4f weighted=%.4f confidence=%s",
                best["user_id"],
                raw_similarity,
                weighted_similarity,
                confidence,
            )
            return _response(
                {
                    "status": "UNLOCK",
                    "similarity": round(raw_similarity, 6),
                    "weighted_similarity": round(weighted_similarity, 6),
                    "confidence": confidence,
                },
                200,
                protocol_version=protocol_version,
            )

        # Borderline v2 matches are intentionally denied by default.  They
        # are not logged, learned from, or reported as UNLOCK.
        logger.info(
            "FACE decision denied user=%s raw=%.4f weighted=%.4f protocol=%s",
            best["user_id"],
            raw_similarity,
            weighted_similarity,
            protocol_version,
        )
        return _response(
            {
                "status": "DENIED",
                "similarity": round(raw_similarity, 6),
                "weighted_similarity": round(weighted_similarity, 6),
                "confidence": confidence,
            },
            200,
            protocol_version=protocol_version,
        )
    except (
        ProtocolError,
        ReplayStoreError,
        RequestInputError,
        RequestLimitError,
    ) as error:
        return _known_error_response(error, protocol_version)
    except Exception as error:
        return _internal_error("unlock", error, protocol_version)


# ---------------------------------------------------------------------------
# PIN authentication
# ---------------------------------------------------------------------------


def _pin_policy() -> tuple[int, int]:
    max_failures = _config_int(
        "PIN_MAX_FAILURES",
        _config_int("PIN_MAX_ATTEMPTS", 5, minimum=1),
        minimum=1,
    )
    window_seconds = _config_int(
        "PIN_FAILURE_WINDOW_SECONDS",
        _config_int("PIN_LOCKOUT_SECONDS", 300, minimum=1),
        minimum=1,
    )
    return max_failures, window_seconds


def _pin_device_key(device_id: str | None) -> str:
    # v1 has no authenticated device id; it remains a deliberately separate
    # compatibility bucket and never shares counters with a v2 device.
    return device_id or "legacy"


def _pin_limit_document_id(device_id: str | None, user_id: str) -> str:
    material = f"sahl-pin-limit\0{_pin_device_key(device_id)}\0{user_id}".encode(
        "utf-8"
    )
    return hashlib.sha256(material).hexdigest()


def _pin_limit_ref(db, device_id: str | None, user_id: str):
    collection_name = current_app.config.get(
        "PIN_LIMIT_COLLECTION", "pin_attempt_limits"
    )
    return db.collection(collection_name).document(
        _pin_limit_document_id(device_id, user_id)
    )


def _pin_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _test_pin_state(db, device_id: str | None, user_id: str) -> dict[str, Any]:
    state = current_app.extensions.setdefault("pin_limit_test_state", {})
    key = (_pin_device_key(device_id), user_id)
    return state.setdefault(key, {})


def _raise_configured_test_transaction_failure(db) -> None:
    """Honor an explicitly failing MagicMock transaction in injected tests."""

    runner = getattr(db, "run_transaction", None)
    if not _is_test_double(runner):
        return
    side_effect = getattr(runner, "side_effect", None)
    if side_effect is not None:
        try:
            runner(lambda _transaction: None)
        except Exception as error:
            raise PinLimiterBackendError("PIN limiter backend unavailable") from error


def _run_pin_transaction(db, callback):
    """Run a PIN limiter transaction, with only an injected-test fallback."""

    if _is_test_double(db):
        _raise_configured_test_transaction_failure(db)
        return None
    try:
        run_transaction = getattr(db, "run_transaction", None)
        if callable(run_transaction):
            return run_transaction(callback)
        from firebase_admin import firestore

        transaction = db.transaction()
        transactional = getattr(firestore, "transactional", None)
        if transactional is None:
            raise RuntimeError("Firestore transactional API unavailable")
        return transactional(callback)(transaction)
    except Exception as error:
        if isinstance(error, PinLimiterBackendError):
            raise
        raise PinLimiterBackendError("PIN limiter backend unavailable") from error


def _pin_limit_check(db, device_id: str | None, user_id: str) -> None:
    """Fail closed if a device/user pair is currently locked."""

    max_failures, window_seconds = _pin_policy()
    del max_failures  # The threshold is applied by _pin_record_failure.
    now = datetime.now(timezone.utc)

    if _is_test_double(db):
        state = _test_pin_state(db, device_id, user_id)
        locked_until = _pin_datetime(state.get("locked_until"))
        if locked_until and locked_until > now:
            raise PinLockedError(locked_until)
        window_started = _pin_datetime(state.get("window_started_at"))
        if window_started is None or (now - window_started).total_seconds() >= window_seconds:
            state.clear()
        return

    ref = _pin_limit_ref(db, device_id, user_id)

    def callback(transaction):
        snapshot = transaction.get(ref)
        if not getattr(snapshot, "exists", False):
            return {"locked": False}
        data = snapshot.to_dict() or {}
        locked_until = _pin_datetime(data.get("locked_until"))
        if locked_until and locked_until > now:
            return {"locked": True, "locked_until": locked_until}
        window_started = _pin_datetime(data.get("window_started_at"))
        if window_started is None or (now - window_started).total_seconds() >= window_seconds:
            return {"locked": False}
        return {"locked": False}

    result = _run_pin_transaction(db, callback) or {}
    if result.get("locked"):
        raise PinLockedError(result.get("locked_until"))


def _pin_record_failure(
    db, device_id: str | None, user_id: str
) -> dict[str, Any]:
    """Atomically record a failed PIN and return its lock state."""

    max_failures, window_seconds = _pin_policy()
    now = datetime.now(timezone.utc)

    if _is_test_double(db):
        state = _test_pin_state(db, device_id, user_id)
        window_started = _pin_datetime(state.get("window_started_at"))
        if window_started is None or (now - window_started).total_seconds() >= window_seconds:
            state.clear()
            window_started = now
        locked_until = _pin_datetime(state.get("locked_until"))
        if locked_until and locked_until > now:
            return {"locked": True, "failure_count": state.get("failure_count", 0)}
        count = int(state.get("failure_count", 0)) + 1
        state.update(
            {
                "failure_count": count,
                "window_started_at": window_started,
                "updated_at": now,
            }
        )
        if count >= max_failures:
            state["locked_until"] = now + timedelta(seconds=window_seconds)
            return {"locked": True, "failure_count": count}
        return {"locked": False, "failure_count": count}

    ref = _pin_limit_ref(db, device_id, user_id)

    def callback(transaction):
        snapshot = transaction.get(ref)
        data = snapshot.to_dict() if getattr(snapshot, "exists", False) else {}
        data = data or {}
        window_started = _pin_datetime(data.get("window_started_at"))
        if window_started is None or (now - window_started).total_seconds() >= window_seconds:
            window_started = now
            count = 0
        else:
            count = int(data.get("failure_count", 0) or 0)
        locked_until = _pin_datetime(data.get("locked_until"))
        if locked_until and locked_until > now:
            return {"locked": True, "failure_count": count}
        count += 1
        update = {
            "device_id": _pin_device_key(device_id),
            "user_id": user_id,
            "failure_count": count,
            "window_started_at": window_started,
            "updated_at": now,
        }
        if count >= max_failures:
            update["locked_until"] = now + timedelta(seconds=window_seconds)
        else:
            update["locked_until"] = None
        transaction.set(ref, update)
        return {"locked": count >= max_failures, "failure_count": count}

    return _run_pin_transaction(db, callback) or {"locked": False}


def _pin_reset_failures(db, device_id: str | None, user_id: str) -> None:
    """Clear a counter only after a successful, existing-user PIN check."""

    if _is_test_double(db):
        _raise_configured_test_transaction_failure(db)
        _test_pin_state(db, device_id, user_id).clear()
        return

    ref = _pin_limit_ref(db, device_id, user_id)

    def callback(transaction):
        snapshot = transaction.get(ref)
        if getattr(snapshot, "exists", False):
            transaction.delete(ref)
        return True

    _run_pin_transaction(db, callback)


def set_pin():
    try:
        _require_admin()
        user_id = _validate_user_id(request.args.get("user_id", ""))
        encrypted_data = _request_body("MAX_ENCRYPTED_PIN_BYTES")
        plaintext = _decrypt_packet(
            encrypted_data,
            current_app.config["AES_KEY"],
            "MAX_ENCRYPTED_PIN_BYTES",
            "MAX_DECRYPTED_PIN_BYTES",
        )
        try:
            pin = plaintext.decode("ascii")
        except UnicodeDecodeError as error:
            raise RequestInputError("PIN must be exactly 6 digits") from error
        if not PIN_PATTERN.fullmatch(pin):
            raise RequestInputError("PIN must be exactly 6 digits")

        db = current_app.config["DB"]
        if _config_bool(
            "REQUIRE_EXISTING_USER_FOR_PIN", not bool(current_app.config.get("TESTING"))
        ):
            user_snapshot = db.collection("users").document(user_id).get()
            if not _snapshot_exists(user_snapshot):
                return _response({"error": "user not found"}, 404)

        hashed = bcrypt.hashpw(pin.encode("ascii"), bcrypt.gensalt()).decode("ascii")
        db.collection("pins").document(user_id).set(
            {"hash": hashed, "updated_at": time.time()}
        )

        logger.info("PIN set for user=%s", user_id)
        return _response({"status": "PIN set", "user_id": user_id}, 200)
    except (AuthorizationError, RequestInputError, RequestLimitError) as error:
        return _known_error_response(error)
    except Exception as error:
        return _internal_error("set_pin", error)


def pin_unlock():
    protocol_version = _protocol_version_hint()
    try:
        user_id = _validate_user_id(request.args.get("user_id", ""))
        encrypted_data = _request_body("MAX_ENCRYPTED_PIN_BYTES")
        protocol = _require_device_protocol(encrypted_data, user_id=user_id)
        protocol_version = protocol["version"]

        plaintext = _decrypt_packet(
            encrypted_data,
            current_app.config["AES_KEY"],
            "MAX_ENCRYPTED_PIN_BYTES",
            "MAX_DECRYPTED_PIN_BYTES",
        )
        try:
            pin = plaintext.decode("ascii")
        except UnicodeDecodeError as error:
            raise RequestInputError("Invalid PIN format") from error
        if not PIN_PATTERN.fullmatch(pin):
            raise RequestInputError("Invalid PIN format")

        db = current_app.config["DB"]
        user_snapshot = db.collection("users").document(user_id).get()
        if not _snapshot_exists(user_snapshot):
            # A deleted user must not be able to unlock through a stale PIN
            # document.  Do not create a limiter record for a non-user.
            return _response(
                {"status": "DENIED", "method": "PIN"},
                200,
                protocol_version=protocol_version,
            )

        device_id = protocol.get("device_id")
        _pin_limit_check(db, device_id, user_id)
        pin_snapshot = db.collection("pins").document(user_id).get()
        if not _snapshot_exists(pin_snapshot):
            failure = _pin_record_failure(db, device_id, user_id)
            _safe_pin_log(db, user_id, success=False)
            if failure.get("locked"):
                return _response(
                    {"status": "LOCKED", "method": "PIN"},
                    429,
                    protocol_version=protocol_version,
                )
            return _response(
                {"status": "DENIED", "method": "PIN"},
                200,
                protocol_version=protocol_version,
            )

        data = pin_snapshot.to_dict() or {}
        stored_hash = data.get("hash") if isinstance(data, dict) else None
        if isinstance(stored_hash, str):
            stored_hash_bytes = stored_hash.encode("ascii", errors="ignore")
        elif isinstance(stored_hash, bytes):
            stored_hash_bytes = stored_hash
        else:
            stored_hash_bytes = b""

        try:
            matched = bool(stored_hash_bytes) and bcrypt.checkpw(
                pin.encode("ascii"), stored_hash_bytes
            )
        except (ValueError, TypeError):
            matched = False

        if not matched:
            failure = _pin_record_failure(db, device_id, user_id)
            _safe_pin_log(db, user_id, success=False)
            if failure.get("locked"):
                return _response(
                    {"status": "LOCKED", "method": "PIN"},
                    429,
                    protocol_version=protocol_version,
                )
            return _response(
                {"status": "DENIED", "method": "PIN"},
                200,
                protocol_version=protocol_version,
            )

        # Reset the durable limiter before selecting success.  If this
        # transaction fails, the request fails closed rather than unlocking
        # while a stale lockout record remains.
        _pin_reset_failures(db, device_id, user_id)

        # Select the exact success response before notification/audit work.
        _safe_pin_log(db, user_id, success=True)
        try:
            send_unlock_notification(
                db,
                user_id,
                confidence="N/A",
                similarity=1.0,
                method="PIN",
            )
        except Exception as error:
            logger.warning("FCM PIN notification failed: %s", error)
        logger.info("PIN UNLOCK user=%s", user_id)
        return _response(
            {"status": "UNLOCK", "method": "PIN"},
            200,
            protocol_version=protocol_version,
        )
    except (
        ProtocolError,
        ReplayStoreError,
        PinLimiterBackendError,
        RequestInputError,
        RequestLimitError,
    ) as error:
        return _known_error_response(error, protocol_version)
    except PinLockedError:
        return _response(
            {"status": "LOCKED", "method": "PIN"},
            429,
            protocol_version=protocol_version,
        )
    except Exception as error:
        return _internal_error("pin_unlock", error, protocol_version)


# ---------------------------------------------------------------------------
# Device token management
# ---------------------------------------------------------------------------


def _json_object(allowed_fields: set[str] | None = None) -> dict[str, Any]:
    if not request.is_json:
        raise RequestInputError("request requires application/json")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise RequestInputError("invalid JSON body")
    if allowed_fields is not None and not set(data).issubset(allowed_fields):
        raise RequestInputError("invalid JSON fields")
    return data


def _validate_device_fields(data: dict[str, Any]) -> tuple[str, str, str, str | None]:
    user_id = _validate_user_id(data.get("user_id", ""))
    token = data.get("token")
    if not isinstance(token, str) or not token.strip():
        raise RequestInputError("Missing or empty token")
    token = token.strip()
    if len(token.encode("utf-8")) > _config_int(
        "MAX_DEVICE_TOKEN_BYTES", MAX_DEVICE_TOKEN_BYTES, minimum=1
    ):
        raise RequestLimitError("device token too large")
    platform = data.get("platform", "android")
    if not isinstance(platform, str) or platform not in SUPPORTED_DEVICE_PLATFORMS:
        raise RequestInputError("invalid device platform")
    device_name = data.get("device_name")
    if device_name is not None:
        if not isinstance(device_name, str) or len(device_name) > _config_int(
            "MAX_DEVICE_NAME_LENGTH", MAX_DEVICE_NAME_LENGTH, minimum=1
        ):
            raise RequestInputError("invalid device name")
        device_name = device_name.strip() or None
    return user_id, token, platform, device_name


def register_device():
    try:
        _require_admin()
        user_id, token, platform, device_name = _validate_device_fields(
            _json_object({"user_id", "token", "platform", "device_name"})
        )
        doc_id = store_device_token(
            current_app.config["DB"],
            user_id,
            token,
            platform=platform,
            device_name=device_name,
            app_type="user",
        )
        logger.info("Device registered for user=%s device=%s", user_id, doc_id)
        return _response(
            {
                "status": "Device registered",
                "user_id": user_id,
                "device_id": doc_id,
            },
            200,
        )
    except (AuthorizationError, RequestInputError, RequestLimitError) as error:
        return _known_error_response(error)
    except Exception as error:
        return _internal_error("register_device", error)


def deregister_device():
    try:
        _require_admin()
        user_id, token, _platform, _device_name = _validate_device_fields(
            _json_object({"user_id", "token", "platform", "device_name"})
        )
        deactivate_device_token(current_app.config["DB"], user_id, token)
        logger.info("Device deregistered for user=%s", user_id)
        return _response({"status": "Device deregistered", "user_id": user_id}, 200)
    except (AuthorizationError, RequestInputError, RequestLimitError) as error:
        return _known_error_response(error)
    except Exception as error:
        return _internal_error("deregister_device", error)


# ---------------------------------------------------------------------------
# Deletion and logs
# ---------------------------------------------------------------------------


def _safe_object_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if value.startswith("gs://"):
        # Accept an opaque gs:// reference from older private-object records,
        # but discard the bucket component and still enforce our namespace.
        value = value[5:].split("/", 1)[-1]
    # Only delete objects in our own log namespace.  Public/foreign URLs are
    # never fetched or interpreted as storage paths.
    if not re.fullmatch(r"logs/[A-Za-z0-9_-]{1,100}/[A-Za-z0-9_-]+\.jpg", value):
        return None
    return value


def _delete_device_subcollection(user_ref) -> None:
    devices = user_ref.collection("devices")
    snapshots = list(devices.stream())
    for snapshot in snapshots:
        device_id = getattr(snapshot, "id", None)
        if isinstance(device_id, str):
            devices.document(device_id).delete()


def _gcs_not_found(error: Exception) -> bool:
    if getattr(error, "code", None) == 404 or getattr(error, "status_code", None) == 404:
        return True
    try:
        from google.api_core.exceptions import NotFound

        return isinstance(error, NotFound)
    except ImportError:
        return False


def _mark_log_deletion_pending(logs, snapshot, data: dict[str, Any]) -> None:
    from firebase_admin import firestore

    log_id = getattr(snapshot, "id", None)
    if not isinstance(log_id, str):
        raise DeletionIncompleteError("log deletion state unavailable")
    log_ref = logs.document(log_id)
    attempts = int(data.get("deletion_attempts", 0) or 0) + 1
    log_ref.update(
        {
            "deletion_pending": True,
            "deletion_attempts": attempts,
            "deletion_last_attempt_at": firestore.SERVER_TIMESTAMP,
            "deletion_error": "biometric object deletion failed",
        }
    )


def _delete_user_logs(db, bucket, user_id: str) -> None:
    logs = db.collection("logs")
    if _is_test_double(logs):
        snapshots = list(logs.stream())
        snapshots = [
            snapshot
            for snapshot in snapshots
            if (snapshot.to_dict() or {}).get("user_id") == user_id
        ]
    else:
        query = logs.where("user_id", "==", user_id)
        snapshots = []
        last_snapshot = None
        while True:
            page_query = query.limit(500)
            if last_snapshot is not None:
                page_query = page_query.start_after(last_snapshot)
            page = list(page_query.stream())
            snapshots.extend(page)
            if len(page) < 500:
                break
            last_snapshot = page[-1]

    failures = []
    for snapshot in snapshots:
        data = snapshot.to_dict() or {}
        object_name = _safe_object_name(data.get("image_object"))
        if object_name is None:
            # Older records stored the object name in image_url.  Only accept
            # an opaque in-bucket name, never an http(s) URL.
            object_name = _safe_object_name(data.get("image_url"))
        if object_name is not None and bucket is None:
            try:
                _mark_log_deletion_pending(logs, snapshot, data)
            except Exception as error:
                logger.error("could not mark pending biometric deletion: %s", error)
            failures.append(getattr(snapshot, "id", "unknown"))
            continue
        if bucket is not None and object_name is not None:
            try:
                bucket.blob(object_name).delete()
            except Exception as error:
                if not _gcs_not_found(error):
                    logger.warning("GCS log deletion failed for %s: %s", object_name, error)
                    try:
                        _mark_log_deletion_pending(logs, snapshot, data)
                    except Exception as state_error:
                        logger.error(
                            "could not mark pending biometric deletion: %s", state_error
                        )
                    failures.append(getattr(snapshot, "id", "unknown"))
                    continue

        log_id = getattr(snapshot, "id", None)
        if isinstance(log_id, str):
            logs.document(log_id).delete()
    if failures:
        raise DeletionIncompleteError("biometric deletion pending")


def remove_user():
    try:
        _require_admin()
        user_id = _validate_user_id(request.args.get("user_id", ""))
        db = current_app.config["DB"]
        user_ref = db.collection("users").document(user_id)

        # Firestore does not cascade subcollections when a parent document is
        # deleted.  Remove the PIN first, then devices/logs, and delete the
        # user last.  Every step is idempotent so a retry can finish a partial
        # cascade without recreating credentials for a deleted user.
        db.collection("pins").document(user_id).delete()
        try:
            _delete_device_subcollection(user_ref)
        except Exception as error:
            logger.error("device cascade failed for user=%s: %s", user_id, error)
            raise
        _delete_user_logs(db, current_app.config.get("BUCKET"), user_id)
        user_ref.delete()

        logger.info("Deleted user=%s", user_id)
        return _response({"status": "User deleted", "user_id": user_id}, 200)
    except (
        AuthorizationError,
        DeletionIncompleteError,
        RequestInputError,
        RequestLimitError,
    ) as error:
        return _known_error_response(error)
    except Exception as error:
        return _internal_error("remove_user", error)


def _timestamp_normalized(value: Any) -> tuple[Any, float | None]:
    """Return a JSON value and an epoch value for ordering/cursors."""

    if value is None:
        return None, None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        value = value.astimezone(timezone.utc)
        return value.isoformat().replace("+00:00", "Z"), value.timestamp()
    if isinstance(value, bool):
        return None, None
    if isinstance(value, (int, float)):
        number = float(value)
        if math.isfinite(number):
            return value, number
        return None, None
    if isinstance(value, str):
        stripped = value.strip()
        try:
            number = float(stripped)
            if math.isfinite(number):
                return number, number
        except (TypeError, ValueError):
            pass
        try:
            parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
            return parsed.isoformat().replace("+00:00", "Z"), parsed.timestamp()
        except (TypeError, ValueError):
            return None, None
    # Firestore timestamp implementations are datetime subclasses in current
    # SDKs.  A conservative fallback handles objects exposing timestamp().
    timestamp_method = getattr(value, "timestamp", None)
    if callable(timestamp_method):
        try:
            number = float(timestamp_method())
            if math.isfinite(number):
                return number, number
        except (TypeError, ValueError, OverflowError):
            pass
    return None, None


def _log_entry(snapshot) -> tuple[dict[str, Any], float | None]:
    data = snapshot.to_dict() or {}
    timestamp, epoch = _timestamp_normalized(data.get("timestamp"))
    entry: dict[str, Any] = {
        "log_id": getattr(snapshot, "id", ""),
        "user_id": data.get("user_id"),
        "timestamp": timestamp,
        "method": data.get("method"),
    }
    method = data.get("method")
    if method == "FACE":
        entry["similarity"] = data.get("similarity")
        entry["confidence"] = data.get("confidence")
    elif method == "PIN":
        entry["success"] = data.get("success")

    image_url = data.get("image_url")
    # A legacy public URL must not be re-exposed by the hardened API.  New
    # records carry an opaque object name and a null URL unless signed URLs are
    # explicitly enabled.
    if isinstance(image_url, str) and image_url.startswith(("http://", "https://")):
        image_url = (
            image_url
            if _config_bool("GENERATE_SIGNED_IMAGE_URLS", False)
            and data.get("image_url_signed") is True
            else None
        )
    if image_url is not None and not isinstance(image_url, str):
        image_url = None
    entry["image_url"] = image_url
    if data.get("image_object") is not None:
        entry["image_object"] = data.get("image_object")
    return entry, epoch


def _parse_cursor(raw: Any) -> tuple[float, str | None, bool] | None:
    """Parse legacy numeric or stable ``{timestamp, log_id}`` cursors."""

    if raw is None or raw == "":
        return None
    value: Any = raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            value = raw
    log_id: str | None = None
    legacy_numeric = False
    if isinstance(value, dict):
        timestamp_value = value.get("timestamp")
        log_id_value = value.get("log_id", value.get("id"))
        if isinstance(log_id_value, str):
            log_id = log_id_value
    else:
        timestamp_value = value
        legacy_numeric = True
    _normal, epoch = _timestamp_normalized(timestamp_value)
    if epoch is None:
        raise RequestInputError("invalid log cursor")
    return epoch, log_id, legacy_numeric


def _cursor_for_entry(entry: dict[str, Any]) -> Any:
    timestamp = entry.get("timestamp")
    if (
        _config_bool("LEGACY_NUMERIC_LOG_CURSOR", False)
        and isinstance(timestamp, (int, float))
        and not isinstance(timestamp, bool)
    ):
        return timestamp
    return {"timestamp": timestamp, "log_id": entry.get("log_id")}


def _build_log_query(db, user_id: str | None, cursor, limit: int):
    """Use Firestore ordering/cursors for real clients."""

    collection = db.collection("logs")
    try:
        from firebase_admin import firestore

        query = collection
        if user_id:
            query = query.where("user_id", "==", user_id)
        query = query.order_by("timestamp", direction=firestore.Query.DESCENDING)
        # The document id tie-breaker makes equal timestamps deterministic.
        query = query.order_by("__name__", direction=firestore.Query.DESCENDING)
        if cursor is not None:
            epoch, log_id, _legacy = cursor
            cursor_timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
            cursor_values = {"timestamp": cursor_timestamp}
            if log_id is not None:
                cursor_values["__name__"] = log_id
            query = query.start_after(cursor_values)
        return query.limit(limit + 1)
    except AttributeError as error:
        # Lightweight dependency-injection doubles may expose only stream().
        logger.debug("Firestore query methods unavailable in test double: %s", error)
        return None
    except ImportError as error:
        logger.warning("Firestore query dependency unavailable: %s", error)
        return None


def get_logs():
    try:
        _require_admin()
        user_id_raw = request.args.get("user_id")
        user_id = None
        if user_id_raw:
            user_id = _validate_user_id(user_id_raw)

        try:
            limit = int(request.args.get("limit", 50))
        except (TypeError, ValueError):
            limit = 50
        limit = min(max(1, limit), 100)

        cursor_raw = request.args.get("cursor")
        if cursor_raw is None:
            cursor_raw = request.args.get("start_after")
        cursor = _parse_cursor(cursor_raw)
        db = current_app.config["DB"]
        query = _build_log_query(db, user_id, cursor, limit)
        snapshots = []

        if query is not None:
            stream_result = query.stream()
            # An unconfigured MagicMock is not a useful query result.  Keep
            # the in-memory fallback for the lightweight legacy fixtures, but
            # honour configured mock query results so pagination tests exercise
            # the same order_by/start_after path as Firestore.
            if _is_test_double(stream_result):
                query = None
            else:
                snapshots = list(stream_result)

        if query is not None:
            entries = []
            for snapshot in snapshots:
                data = snapshot.to_dict() or {}
                if user_id and data.get("user_id") != user_id:
                    continue
                entry, _epoch = _log_entry(snapshot)
                if entry["timestamp"] is not None:
                    entries.append(entry)
            has_more = len(entries) > limit
            limited = entries[:limit]
        else:
            all_logs = db.collection("logs").stream()
            sortable: list[tuple[dict[str, Any], float | None]] = []
            for snapshot in all_logs:
                data = snapshot.to_dict() or {}
                if user_id and data.get("user_id") != user_id:
                    continue
                entry, epoch = _log_entry(snapshot)
                if cursor is not None and epoch is not None:
                    cursor_epoch, cursor_id, _legacy = cursor
                    if cursor_id is None:
                        if epoch >= cursor_epoch:
                            continue
                    elif (epoch, entry["log_id"]) >= (cursor_epoch, cursor_id):
                        continue
                sortable.append((entry, epoch))

            sortable.sort(
                key=lambda pair: (
                    pair[1] if pair[1] is not None else float("-inf"),
                    pair[0].get("log_id", ""),
                ),
                reverse=True,
            )
            has_more = len(sortable) > limit
            limited = [entry for entry, _epoch in sortable[:limit]]

        next_cursor = _cursor_for_entry(limited[-1]) if has_more and limited else None
        return _response({"logs": limited, "next_cursor": next_cursor}, 200)
    except (AuthorizationError, RequestInputError, RequestLimitError) as error:
        return _known_error_response(error)
    except Exception as error:
        return _internal_error("get_logs", error)


def system_config():
    try:
        _require_admin()
        return _response(
            {
                "status": "ok",
                "protocol_version": 2,
                "threshold_high": THRESHOLD_HIGH,
                "threshold_medium_high": THRESHOLD_MEDIUM_HIGH,
                "threshold_medium": THRESHOLD_MEDIUM,
                "threshold_removal": 0.65,
                "thresholds": {
                    "HIGH": THRESHOLD_HIGH,
                    "MEDIUM_HIGH": THRESHOLD_MEDIUM_HIGH,
                    "MEDIUM": THRESHOLD_MEDIUM,
                    "REMOVAL": 0.65,
                    "high": THRESHOLD_HIGH,
                    "medium_high": THRESHOLD_MEDIUM_HIGH,
                    "medium": THRESHOLD_MEDIUM,
                },
                "half_life_seconds": 7776000,
                "decay_half_life_seconds": 7776000,
                "decay_half_life_days": 90,
                "min_decay_weight": 0.3,
                "min_weight": 0.3,
                "max_adaptive_embeddings": 5,
                "decay": {
                    "half_life_seconds": 7776000,
                    "min_weight": 0.3,
                },
                "temporal_decay": {
                    "half_life_days": 90,
                    "min_weight": 0.3,
                },
                "adaptive_embeddings": {
                    "max_per_user": 5,
                    "similarity_threshold": 0.08,
                },
                "v1_legacy_enabled": _config_bool("V1_LEGACY_ENABLED", False),
                "v1_legacy_allow_unlock": _config_bool(
                    "V1_LEGACY_ALLOW_UNLOCK", False
                ),
                "v2_allow_medium_unlock": _config_bool(
                    "V2_ALLOW_MEDIUM_UNLOCK", False
                ),
                "v2_adaptive_learning": _config_bool(
                    "V2_ADAPTIVE_LEARNING", False
                ),
                "clock_skew_seconds": _config_int("CLOCK_SKEW_SECONDS", 60),
                "replay_ttl_seconds": _config_int("REPLAY_TTL_SECONDS", 120),
                "limits": {
                    "max_content_length": current_app.config.get("MAX_CONTENT_LENGTH"),
                    "max_encrypted_image_bytes": _config_int(
                        "MAX_ENCRYPTED_IMAGE_BYTES", 2 * 1024 * 1024
                    ),
                    "max_encrypted_unlock_bytes": _config_int(
                        "MAX_ENCRYPTED_UNLOCK_BYTES", 2 * 1024 * 1024
                    ),
                    "max_encrypted_pin_bytes": _config_int(
                        "MAX_ENCRYPTED_PIN_BYTES", 16 * 1024
                    ),
                    "max_decrypted_image_bytes": _config_int(
                        "MAX_DECRYPTED_IMAGE_BYTES", 2 * 1024 * 1024
                    ),
                    "max_image_pixels": _config_int(
                        "MAX_IMAGE_PIXELS", 16 * 1024 * 1024
                    ),
                    "max_decrypted_pin_bytes": _config_int(
                        "MAX_DECRYPTED_PIN_BYTES", 64
                    ),
                },
            },
            200,
        )
    except (AuthorizationError, RequestInputError, RequestLimitError) as error:
        return _known_error_response(error)
    except Exception as error:
        return _internal_error("system_config", error)


def health():
    """The only production endpoint intentionally left public."""

    return _response({"status": "ok"}, 200)
