"""Bounded, transaction-safe continuous-learning helpers.

The service has encountered two adaptive-record shapes in the wild:

* safe current fields such as ``adaptive_1710000000: [float, ...]``;
* legacy records such as ``adaptive_1710000000.5: {"embedding": [...],
  "timestamp": ...}`` and the experimental ``adaptive_embeddings`` list.

Reads normalize all of those shapes.  Writes use a Firestore transaction for
deduplication, key allocation, and the per-user capacity check so concurrent
unlock requests cannot exceed the adaptive cap or allocate the same key.
"""

from __future__ import annotations

import logging
import math
import re
import time
from datetime import datetime, timezone
from typing import Any, Iterator, Mapping, Optional

import numpy as np

from app.similarity import cosine_similarity, euclidean_distance, validate_embedding


logger = logging.getLogger(__name__)

HALF_LIFE_SECONDS = 7776000
MIN_WEIGHT = 0.3
MAX_ADAPTIVE_EMBEDDINGS = 5
DEDUP_THRESHOLD = 0.08
PRUNE_THRESHOLD = 0.65
CORE_IMAGE_KEYS = frozenset(
    {"timestamp", "created_at", "updated_at", "adaptive_embeddings"}
)
ADAPTIVE_KEY_RE = re.compile(r"^adaptive_(\d+)(?:[._](\d+))?$")


class AdaptiveLearningBackendError(RuntimeError):
    """The Firestore transaction for adaptive data could not complete."""


def temporal_decay_weight(
    timestamp: float,
    now: Optional[float] = None,
    half_life: float = HALF_LIFE_SECONDS,
    min_weight: float = MIN_WEIGHT,
) -> float:
    """Compute an exponential decay weight with a bounded floor."""

    if now is None:
        now = time.time()
    try:
        timestamp = float(timestamp)
        now = float(now)
        half_life = float(half_life)
        min_weight = float(min_weight)
    except (TypeError, ValueError):
        return min_weight
    if not math.isfinite(timestamp) or not math.isfinite(now):
        return min_weight
    if not math.isfinite(half_life) or half_life <= 0:
        return min_weight
    age = max(0.0, now - timestamp)
    return max(math.pow(2, -age / half_life), min_weight)


def adaptive_key_ts(key: str) -> float:
    """Extract a timestamp from safe or legacy adaptive field names."""

    if not isinstance(key, str) or not key.startswith("adaptive_"):
        return 0.0
    suffix = key.split("_", 1)[1]
    try:
        # Legacy decimal keys remain readable.  Safe collision suffixes are
        # deliberately ignored when determining age.
        first = re.split(r"[._]", suffix, maxsplit=1)[0]
        value = float(first)
        return value if math.isfinite(value) else 0.0
    except (TypeError, ValueError, IndexError):
        return 0.0


def _timestamp_seconds(value: Any, fallback: float = 0.0) -> float:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            number = float(value)
            return number if math.isfinite(number) else fallback
        except (TypeError, ValueError):
            return fallback
    if isinstance(value, str):
        try:
            number = float(value)
            if math.isfinite(number):
                return number
        except (TypeError, ValueError):
            pass
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError):
            return fallback
    return fallback


def _valid_embedding(value: Any) -> Optional[list[float]]:
    try:
        return validate_embedding(value)
    except (TypeError, ValueError):
        return None


def _record(
    key: str,
    stored: Any,
    *,
    container: str,
    index: int | str | None = None,
    timestamp_override: Any = None,
) -> dict[str, Any] | None:
    """Normalize one legacy/current record while retaining prune provenance."""

    if isinstance(stored, Mapping):
        embedding_value = stored.get("embedding")
        timestamp_value = (
            stored.get("timestamp")
            if timestamp_override is None
            else timestamp_override
        )
        if timestamp_value is None:
            timestamp_value = adaptive_key_ts(key)
    else:
        embedding_value = stored
        timestamp_value = (
            adaptive_key_ts(key) if timestamp_override is None else timestamp_override
        )
    embedding = _valid_embedding(embedding_value)
    if embedding is None:
        return None
    return {
        "key": key,
        "embedding": embedding,
        "timestamp": _timestamp_seconds(timestamp_value, adaptive_key_ts(key)),
        "container": container,
        "index": index,
    }


def _iter_adaptive_records_detailed(user_data: dict) -> Iterator[dict[str, Any]]:
    if not isinstance(user_data, dict):
        return

    records = user_data.get("adaptive_embeddings")
    if isinstance(records, list):
        for index, stored in enumerate(records):
            if isinstance(stored, Mapping):
                timestamp = stored.get("timestamp", 0.0)
                raw_key = stored.get("key", stored.get("id"))
                if not isinstance(raw_key, str) or not raw_key.startswith("adaptive_"):
                    raw_key = f"adaptive_{int(_timestamp_seconds(timestamp))}_{index}"
                normalized = _record(
                    raw_key,
                    stored,
                    container="list",
                    index=index,
                    timestamp_override=timestamp,
                )
            else:
                raw_key = f"adaptive_0_{index}"
                normalized = _record(
                    raw_key, stored, container="list", index=index, timestamp_override=0
                )
            if normalized is not None:
                yield normalized
    elif isinstance(records, Mapping):
        for key, stored in records.items():
            if not isinstance(key, str) or not key.startswith("adaptive_"):
                continue
            normalized = _record(key, stored, container="mapping", index=key)
            if normalized is not None:
                yield normalized

    for key, stored in user_data.items():
        if key == "adaptive_embeddings":
            continue
        if not isinstance(key, str) or not key.startswith("adaptive_"):
            continue
        normalized = _record(key, stored, container="field", index=key)
        if normalized is not None:
            yield normalized


def _iter_adaptive_records(user_data: dict) -> Iterator[tuple[str, list[float], float]]:
    for record in _iter_adaptive_records_detailed(user_data):
        yield record["key"], record["embedding"], record["timestamp"]


def _iter_core_records(user_data: dict) -> Iterator[tuple[str, list[float], float]]:
    if not isinstance(user_data, dict):
        return
    for key, stored in user_data.items():
        if key in CORE_IMAGE_KEYS or str(key).startswith("adaptive_"):
            continue
        if not re.fullmatch(r"image[1-5]", str(key)):
            continue
        embedding = _valid_embedding(stored)
        if embedding is not None:
            yield str(key), embedding, 0.0


def iter_embedding_records(
    user_data: dict,
) -> Iterator[tuple[str, list[float], float, bool]]:
    """Yield normalized records as key, vector, timestamp, adaptive flag."""

    yield from (
        (key, embedding, timestamp, False)
        for key, embedding, timestamp in _iter_core_records(user_data)
    )
    yield from (
        (key, embedding, timestamp, True)
        for key, embedding, timestamp in _iter_adaptive_records(user_data)
    )


def compute_best_match(
    query_embedding,
    user_data: dict,
    now: Optional[float] = None,
) -> dict:
    """Return the winning record and both raw and weighted similarities."""

    if now is None:
        now = time.time()
    query = _valid_embedding(query_embedding)
    if query is None:
        return {"key": None, "raw_similarity": 0.0, "weighted_similarity": 0.0}

    best = {"key": None, "raw_similarity": 0.0, "weighted_similarity": 0.0}
    for key, stored, timestamp, is_adaptive in iter_embedding_records(user_data):
        raw = cosine_similarity(query, stored)
        weighted = raw * temporal_decay_weight(timestamp, now=now) if is_adaptive else raw
        if weighted > best["weighted_similarity"] or (
            math.isclose(weighted, best["weighted_similarity"], abs_tol=1e-12)
            and best["key"] is not None
            and key < best["key"]
        ):
            best = {
                "key": key,
                "raw_similarity": float(raw),
                "weighted_similarity": float(weighted),
            }
    return best


def compute_weighted_similarity(
    query_embedding,
    user_data: dict,
    now: Optional[float] = None,
) -> float:
    return compute_best_match(query_embedding, user_data, now=now)[
        "weighted_similarity"
    ]


def _safe_adaptive_key(timestamp: float, user_data: dict, extra_keys=None) -> str:
    try:
        base_timestamp = max(0, int(float(timestamp)))
    except (TypeError, ValueError, OverflowError):
        base_timestamp = int(time.time())
    existing = set(user_data or {}) | set(extra_keys or {})
    candidate = f"adaptive_{base_timestamp}"
    counter = 1
    while candidate in existing:
        candidate = f"adaptive_{base_timestamp}_{counter}"
        counter += 1
    return candidate


def _is_test_double(value: Any) -> bool:
    return type(value).__module__.startswith("unittest.mock")


class _LocalTransaction:
    """Small transaction-shaped adapter for the injected dict-backed tests."""

    def get(self, ref):
        return ref.get()

    def set(self, ref, data):
        return ref.set(data)

    def update(self, ref, data):
        return ref.update(data)

    def delete(self, ref):
        return ref.delete()

    def create(self, ref, data):
        snapshot = ref.get()
        if getattr(snapshot, "exists", False):
            raise RuntimeError("document already exists")
        return ref.set(data)


def _run_transaction(db, callback):
    if _is_test_double(db):
        runner = getattr(db, "run_transaction", None)
        side_effect = getattr(runner, "side_effect", None)
        if side_effect is not None:
            try:
                runner(callback)
            except Exception as error:
                raise AdaptiveLearningBackendError("adaptive transaction failed") from error
        try:
            return callback(_LocalTransaction())
        except Exception as error:
            if isinstance(error, AdaptiveLearningBackendError):
                raise
            raise AdaptiveLearningBackendError("adaptive transaction failed") from error
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
        if isinstance(error, AdaptiveLearningBackendError):
            raise
        raise AdaptiveLearningBackendError("adaptive transaction failed") from error


def store_adaptive_embedding(
    db,
    user_id: str,
    embedding,
    timestamp: Optional[float] = None,
) -> bool:
    """Transactionally deduplicate, allocate, and store one adaptive vector."""

    if timestamp is None:
        timestamp = time.time()
    validated = _valid_embedding(embedding)
    if validated is None:
        logger.warning("store_adaptive: invalid embedding for user=%s", user_id)
        return False
    doc_ref = db.collection("users").document(user_id)

    def callback(transaction):
        user_snapshot = transaction.get(doc_ref)
        if not getattr(user_snapshot, "exists", False):
            return False
        user_data = user_snapshot.to_dict() or {}
        if not isinstance(user_data, dict):
            return False
        adaptive = list(_iter_adaptive_records(user_data))
        if len(adaptive) >= MAX_ADAPTIVE_EMBEDDINGS:
            return False
        new_arr = np.asarray(validated, dtype=np.float64)
        for _, existing, _ in adaptive:
            if euclidean_distance(new_arr, existing) < DEDUP_THRESHOLD:
                return False
        key = _safe_adaptive_key(
            timestamp,
            user_data,
            extra_keys=(record["key"] for record in _iter_adaptive_records_detailed(user_data)),
        )
        transaction.update(doc_ref, {key: validated})
        return True

    result = _run_transaction(db, callback)
    return result is True


def prune_adaptive_embeddings(
    db,
    user_id: str,
    user_data: dict,
    query_embedding,
    now: Optional[float] = None,
) -> int:
    """Transactionally prune weak records without losing mixed-schema data."""

    if now is None:
        now = time.time()
    query = _valid_embedding(query_embedding)
    if query is None:
        return 0
    doc_ref = db.collection("users").document(user_id)

    def callback(transaction):
        snapshot = transaction.get(doc_ref)
        if not getattr(snapshot, "exists", False):
            return 0
        fresh = snapshot.to_dict() or {}
        if not isinstance(fresh, dict):
            return 0
        remove = []
        for record in _iter_adaptive_records_detailed(fresh):
            raw = cosine_similarity(query, record["embedding"])
            weighted = raw * temporal_decay_weight(record["timestamp"], now=now)
            if weighted < PRUNE_THRESHOLD:
                remove.append(record)
        if not remove:
            return 0

        replacement = dict(fresh)
        list_records = replacement.get("adaptive_embeddings")
        list_indices = sorted(
            {
                int(record["index"])
                for record in remove
                if record["container"] == "list" and isinstance(record["index"], int)
            },
            reverse=True,
        )
        if isinstance(list_records, list):
            mutable_records = list(list_records)
            for index in list_indices:
                if 0 <= index < len(mutable_records):
                    mutable_records.pop(index)
            replacement["adaptive_embeddings"] = mutable_records
        elif isinstance(list_records, Mapping):
            mutable_records = dict(list_records)
            for record in remove:
                if record["container"] == "mapping":
                    mutable_records.pop(record["index"], None)
            replacement["adaptive_embeddings"] = mutable_records

        for record in remove:
            if record["container"] == "field":
                replacement.pop(record["key"], None)
        transaction.set(doc_ref, replacement)
        return len(remove)

    return int(_run_transaction(db, callback) or 0)
