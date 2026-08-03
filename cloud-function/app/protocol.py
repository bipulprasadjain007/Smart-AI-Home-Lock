"""Protocol v2 primitives used by the cloud API.

The encrypted request body is deliberately not changed by protocol v2.  v2
adds authenticated transport metadata around the existing AES-GCM packet:

``X-Protocol-Version: 2``
``X-Device-ID``
``X-Timestamp``
``X-Request-Nonce``
``X-Request-Signature``

This module contains no Flask code so the wire contract can be tested without
initialising a Cloud Function.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode


PROTOCOL_V1 = 1
PROTOCOL_V2 = 2
REPLAY_NAMESPACE = b"sahl-v2-replay\0"
DEFAULT_CLOCK_SKEW_SECONDS = 60
DEFAULT_REPLAY_TTL_SECONDS = 120

REQUEST_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
REQUEST_SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
# Device identifiers are provisioned into headers, Firestore document keys,
# and rate-limit keys.  Keep the grammar deliberately small and bounded so a
# device id cannot smuggle path punctuation or an unbounded value into any of
# those stores.
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
USER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,100}$")


class ProtocolError(ValueError):
    """A request failed protocol parsing or authentication."""

    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.status_code = status_code


class ReplayStoreError(RuntimeError):
    """The replay reservation could not be committed atomically."""


class ReplayDetected(ProtocolError):
    """The request nonce was already reserved."""

    def __init__(self):
        super().__init__("request replayed", status_code=409)


def _decode_credentials_json(value: Any) -> Any:
    if value is None or value == "":
        return {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("DEVICE_CREDENTIALS_JSON must be valid JSON") from exc
    return value


def _key_bytes(value: Any) -> bytes:
    """Decode a credential key, accepting only an explicit 32-byte value."""
    if isinstance(value, bytes):
        key = value
    elif isinstance(value, bytearray):
        key = bytes(value)
    elif isinstance(value, str):
        # Device provisioning uses hex so accidental base64/password values do
        # not silently become HMAC keys.
        if len(value) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("device HMAC key must be 64 hexadecimal characters")
        try:
            key = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("device HMAC key is not valid hexadecimal") from exc
    else:
        raise ValueError("device HMAC key must be bytes or hexadecimal text")
    if len(key) != 32:
        raise ValueError("device HMAC key must be exactly 32 bytes")
    return key


def _credential_entries(value: Any) -> list[tuple[str, Any]]:
    """Return ``(device_id, spec)`` pairs for supported secret layouts.

    The documented layout is a map keyed by device id.  A list and a
    ``{"devices": [...]}`` wrapper are also accepted because Secret Manager
    configuration is commonly generated from either shape.  All shapes are
    normalised and validated before they reach request handling.
    """
    value = _decode_credentials_json(value)
    if isinstance(value, Mapping) and "devices" in value:
        value = value["devices"]

    if isinstance(value, Mapping):
        entries: list[tuple[str, Any]] = []
        for device_id, spec in value.items():
            entries.append((str(device_id), spec))
        return entries

    if isinstance(value, list):
        entries = []
        for spec in value:
            if not isinstance(spec, Mapping):
                raise ValueError("each device credential must be an object")
            device_id = spec.get("device_id", spec.get("id"))
            if device_id is None:
                raise ValueError("each device credential needs device_id")
            entries.append((str(device_id), spec))
        return entries

    raise ValueError("device credentials must be an object or list")


def parse_device_credentials(value: Any) -> dict[str, dict[str, Any]]:
    """Validate and normalise ``DEVICE_CREDENTIALS_JSON``.

    Result values contain raw key bytes, an enabled flag, and a frozen set of
    explicitly permitted user ids.  Wildcards are intentionally rejected:
    device authorization must be auditable and user-scoped.
    """
    credentials: dict[str, dict[str, Any]] = {}
    for device_id, spec in _credential_entries(value):
        if not DEVICE_ID_RE.fullmatch(device_id):
            raise ValueError("invalid device id in device credentials")
        if device_id in credentials:
            raise ValueError("duplicate device id in device credentials")

        if isinstance(spec, Mapping):
            key_value = (
                spec.get("hmac_key_hex")
                or spec.get("hmac_key")
                or spec.get("key")
                or spec.get("secret")
            )
            if key_value is None:
                raise ValueError("device credential is missing hmac_key")
            enabled = spec.get("enabled")
            if not isinstance(enabled, bool):
                raise ValueError("device credential enabled must be boolean")
            allowed_value = spec.get("allowed_user_ids")
            if not isinstance(allowed_value, list):
                raise ValueError("device credential needs allowed_user_ids list")
        else:
            # A bare key used to imply enabled=True and an allow-all/implicit
            # device.  That shape is ambiguous and is not safe for production
            # authentication, so every credential must be an explicit object.
            raise ValueError(
                "device credential must explicitly define enabled and allowed_user_ids"
            )

        key = _key_bytes(key_value)
        if not isinstance(allowed_value, list):
            raise ValueError("allowed_user_ids must be a list")
        allowed: set[str] = set()
        for user_id in allowed_value:
            if not isinstance(user_id, str) or not USER_ID_RE.fullmatch(user_id):
                raise ValueError("allowed_user_ids contains an invalid user id")
            if user_id == "*":
                raise ValueError("wildcard allowed_user_ids are not permitted")
            allowed.add(user_id)

        credentials[device_id] = {
            "key": key,
            "enabled": enabled,
            "allowed_user_ids": frozenset(allowed),
        }
    return credentials


def canonical_query_string(query_string: str | bytes | None) -> str:
    """Canonicalise a URL query for signing.

    Query pairs are decoded, sorted by name and value, then encoded using the
    standard URL form encoding.  This makes equivalent parameter ordering
    produce one signature while retaining duplicate parameters and blanks.
    """
    if query_string is None:
        return ""
    if isinstance(query_string, bytes):
        try:
            query_string = query_string.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProtocolError("invalid query encoding", 400) from exc
    if not isinstance(query_string, str):
        raise ProtocolError("invalid query", 400)
    try:
        pairs = parse_qsl(query_string, keep_blank_values=True, strict_parsing=False)
    except ValueError as exc:
        raise ProtocolError("invalid query", 400) from exc
    pairs.sort(key=lambda pair: (pair[0], pair[1]))
    return urlencode(pairs, doseq=True)


def sha256_body_hex(body: bytes) -> str:
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    return hashlib.sha256(body).hexdigest()


def canonical_string(
    method: str,
    path: str,
    canonical_query: str,
    device_id: str,
    timestamp: str | int,
    request_nonce_hex: str,
    sha256_body_hex_value: str,
) -> str:
    """Build the exact eight-line v2 HMAC input string."""
    fields = [
        "SAHL-V2",
        str(method).upper(),
        path,
        canonical_query,
        device_id,
        str(timestamp),
        request_nonce_hex,
        sha256_body_hex_value,
    ]
    if any("\n" in field or "\r" in field for field in fields):
        raise ProtocolError("invalid signing field", 400)
    return "\n".join(fields)


def sign_request(
    key: bytes | str,
    method: str,
    path: str,
    canonical_query: str,
    device_id: str,
    timestamp: str | int,
    request_nonce_hex: str,
    body: bytes,
) -> str:
    """Return a lowercase HMAC-SHA256 signature for a v2 request."""
    key_bytes = _key_bytes(key)
    if not REQUEST_NONCE_RE.fullmatch(request_nonce_hex):
        raise ProtocolError("invalid request nonce", 400)
    message = canonical_string(
        method,
        path,
        canonical_query,
        device_id,
        timestamp,
        request_nonce_hex,
        sha256_body_hex(body),
    )
    return hmac.new(key_bytes, message.encode("utf-8"), hashlib.sha256).hexdigest()


def replay_document_id(device_id: str, request_nonce_hex: str) -> str:
    """Return the deterministic Firestore id for a v2 replay reservation."""
    material = (
        REPLAY_NAMESPACE
        + device_id.encode("utf-8")
        + b"\0"
        + request_nonce_hex.encode("ascii")
    )
    return hashlib.sha256(material).hexdigest()


def _expiry_is_future(value: Any, now: float) -> bool:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp() > now
    if isinstance(value, (int, float)):
        return float(value) > now
    return True


def reserve_replay(
    db,
    device_id: str,
    request_nonce_hex: str,
    *,
    now: float | None = None,
    ttl_seconds: int = DEFAULT_REPLAY_TTL_SECONDS,
) -> bool:
    """Atomically reserve a request nonce in Firestore.

    ``True`` means this invocation created the reservation; ``False`` means a
    live reservation already exists.  Any transaction/client failure raises
    :class:`ReplayStoreError` so callers can fail closed with HTTP 503.
    """
    if now is None:
        now = time.time()
    if not DEVICE_ID_RE.fullmatch(device_id) or not REQUEST_NONCE_RE.fullmatch(
        request_nonce_hex
    ):
        raise ReplayStoreError("invalid replay key")

    try:
        from firebase_admin import firestore

        replay_id = replay_document_id(device_id, request_nonce_hex)
        ref = db.collection("device_request_replays").document(replay_id)
        expires_at = datetime.fromtimestamp(
            now + int(ttl_seconds), tz=timezone.utc
        )

        def callback(transaction):
            snapshot = transaction.get(ref)
            if getattr(snapshot, "exists", False):
                data = snapshot.to_dict() or {}
                if _expiry_is_future(data.get("expires_at"), now):
                    return False
                # Firestore TTL deletion is asynchronous.  Once expired, the
                # same id can be atomically renewed in this transaction.
                transaction.set(
                    ref,
                    {
                        "device_id": device_id,
                        "request_nonce": request_nonce_hex,
                        "expires_at": expires_at,
                    },
                )
                return True
            transaction.create(
                ref,
                {
                    "device_id": device_id,
                    "request_nonce": request_nonce_hex,
                    "expires_at": expires_at,
                },
            )
            return True

        # Client.run_transaction is the supported Admin SDK path and retries
        # transaction conflicts.  The fallback is useful for lightweight
        # Firestore test doubles and still uses the SDK transactional wrapper.
        run_transaction = getattr(db, "run_transaction", None)
        if callable(run_transaction):
            result = run_transaction(callback)
        else:
            transaction = db.transaction()
            transactional = getattr(firestore, "transactional", None)
            if transactional is None:
                raise RuntimeError("Firestore transactional API unavailable")
            result = transactional(callback)(transaction)
        return bool(result)
    except Exception as exc:
        # A replay result is a normal return value; every other Firestore
        # exception is deliberately collapsed into the fail-closed error.
        if isinstance(exc, ReplayStoreError):
            raise
        raise ReplayStoreError("replay reservation failed") from exc
