"""FCM push notification helpers for Smart AI Home Lock.

Handles device token management and unlock event notifications.
All Firestore writes go through the Admin SDK (db parameter).
"""

from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


# ── Token Management ──────────────────────────────────────────────────────


def store_device_token(
    db,
    user_id: str,
    token: str,
    platform: str = "android",
    device_name: Optional[str] = None,
    app_type: str = "user",
) -> str:
    """Store or update an FCM device token for a user.

    Deduplicates by token so the same device re-registering
    updates its metadata rather than creating a duplicate.

    Returns the device document ID.
    """
    from firebase_admin import firestore

    devices_ref = db.collection("users").document(user_id).collection("devices")

    # Check if this token already exists (same device re-registering)
    existing = devices_ref.where("token", "==", token).limit(1).get()
    if existing:
        doc_ref = existing[0].reference
        doc_ref.update({
            "last_seen_at": firestore.SERVER_TIMESTAMP,
            "platform": platform,
            "device_name": device_name,
            "is_active": True,
        })
        logger.info("Updated existing FCM token for user=%s device=%s", user_id, doc_ref.id)
        return doc_ref.id

    # New device
    doc_ref = devices_ref.document()
    doc_ref.set({
        "token": token,
        "platform": platform,
        "device_name": device_name or f"Device-{doc_ref.id[:6]}",
        "app_type": app_type,
        "created_at": firestore.SERVER_TIMESTAMP,
        "last_seen_at": firestore.SERVER_TIMESTAMP,
        "is_active": True,
    })
    logger.info("Stored new FCM token for user=%s device=%s app=%s", user_id, doc_ref.id, app_type)
    return doc_ref.id


def get_active_tokens_for_user(db, user_id: str) -> list[str]:
    """Get all active, deduplicated FCM tokens for a user.

    Returns a list of unique token strings ready for multicast.
    """
    devices = (
        db.collection("users")
        .document(user_id)
        .collection("devices")
        .where("is_active", "==", True)
        .stream()
    )
    seen = set()
    tokens = []
    for d in devices:
        tok = d.get("token")
        if tok and tok not in seen:
            seen.add(tok)
            tokens.append(tok)
    return tokens


def deactivate_device_token(db, user_id: str, token: str) -> bool:
    """Deactivate a device token (logout or invalid token cleanup).

    Returns True if a matching token was found and deactivated.
    """
    from firebase_admin import firestore

    devices = (
        db.collection("users")
        .document(user_id)
        .collection("devices")
        .where("token", "==", token)
        .limit(1)
        .get()
    )
    found = False
    for doc in devices:
        doc.reference.update({
            "is_active": False,
            "last_seen_at": firestore.SERVER_TIMESTAMP,
        })
        logger.info("Deactivated FCM token for user=%s device=%s", user_id, doc.id)
        found = True
    return found


# ── Notification Building ────────────────────────────────────────────────


def _build_notification_title_body(confidence: str, user_id: str, method: str) -> tuple[str, str]:
    """Build human-readable title and body for unlock notification."""
    if method.upper() == "PIN":
        return ("Door Unlocked", f"{user_id} unlocked via PIN")
    elif confidence == "HIGH":
        return ("Door Unlocked", f"{user_id} unlocked (high confidence)")
    elif confidence in ("MEDIUM-HIGH", "MEDIUM"):
        return ("Door Unlocked", f"{user_id} unlocked — verify identity")
    else:
        return ("Security Alert", "Unrecognized face detected")


def build_unlock_multicast(
    tokens: list[str],
    user_id: str,
    confidence: str,
    similarity: float,
    method: str = "FACE",
    image_url: Optional[str] = None,
):
    """Build a MulticastMessage for an unlock event.

    All devices for a user receive the same notification+data payload.
    Uses platform-specific config for high-priority delivery.

    Returns a firebase_admin.messaging.MulticastMessage ready to send.
    """
    from firebase_admin import messaging

    title, body = _build_notification_title_body(confidence, user_id, method)
    timestamp = int(time.time())

    data = {
        "type": "unlock_event",
        "user_id": user_id,
        "timestamp": str(timestamp),
        "confidence": confidence,
        "similarity": str(round(similarity, 4)),
        "method": method.lower(),
        "image_url": image_url or "",
    }

    return messaging.MulticastMessage(
        notification=messaging.Notification(title=title, body=body),
        data=data,
        tokens=tokens,
        android=messaging.AndroidConfig(
            priority="high",
            ttl=60,
            notification=messaging.AndroidNotification(
                channel_id="unlock_alerts",
                sound="default",
                priority="max",
                visibility="public",
            ),
        ),
        apns=messaging.APNSConfig(
            headers={"apns-priority": "10"},
            payload=messaging.APNSPayload(
                aps=messaging.Aps(
                    sound="default",
                    content_available=True,
                    mutable_content=True,
                    category="UNLOCK_EVENT",
                ),
            ),
        ),
    )


# ── Send + Cleanup ────────────────────────────────────────────────────────


def send_unlock_notification(
    db,
    user_id: str,
    confidence: str,
    similarity: float,
    method: str = "FACE",
    image_url: Optional[str] = None,
) -> dict:
    """Send FCM push notification to all devices for a user.

    Handles invalid token detection and cleanup automatically.
    Non-fatal — errors are logged but never crash the caller.

    Returns {"success": N, "failure": N, "cleaned": N}
    """
    from firebase_admin import messaging

    tokens = get_active_tokens_for_user(db, user_id)
    if not tokens:
        logger.debug("No active FCM tokens for user=%s", user_id)
        return {"success": 0, "failure": 0, "cleaned": 0}

    multicast = build_unlock_multicast(
        tokens=tokens,
        user_id=user_id,
        confidence=confidence,
        similarity=similarity,
        method=method,
        image_url=image_url,
    )

    try:
        response = messaging.send_each_for_multicast(multicast)
    except Exception as e:
        logger.error("FCM multicast send failed: %s", e)
        return {"success": 0, "failure": len(tokens), "cleaned": 0}

    # Clean up invalid tokens
    cleaned = 0
    for i, send_response in enumerate(response.responses):
        if not send_response.success:
            exception = send_response.exception
            bad_token = tokens[i]

            should_delete = (
                isinstance(exception, messaging.UnregisteredError)
                or isinstance(exception, messaging.SenderIdMismatchError)
                or (
                    exception is not None
                    and "Invalid registration token" in str(exception)
                )
            )

            if should_delete:
                logger.warning(
                    "Removing invalid FCM token for user=%s: %s (reason: %s)",
                    user_id, bad_token[:10] + "...", type(exception).__name__,
                )
                deactivate_device_token(db, user_id, bad_token)
                cleaned += 1
            else:
                logger.warning(
                    "FCM transient error for user=%s: %s",
                    user_id, exception,
                )

    logger.info(
        "FCM: %d sent, %d failed, %d tokens cleaned for user=%s",
        response.success_count, response.failure_count, cleaned, user_id,
    )

    return {
        "success": response.success_count,
        "failure": response.failure_count,
        "cleaned": cleaned,
    }
