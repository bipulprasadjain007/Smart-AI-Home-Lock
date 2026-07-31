"""Continuous learning engine for adaptive face embeddings.

Implements temporal decay, weighted similarity scoring, adaptive embedding
storage with deduplication, and pruning of stale/weak embeddings.
"""

import math
import time
import logging
from typing import Optional

import numpy as np

from app.similarity import cosine_similarity, euclidean_distance

logger = logging.getLogger(__name__)

HALF_LIFE_SECONDS = 7776000   # 90 days in seconds
MIN_WEIGHT = 0.3               # minimum decay weight floor
MAX_ADAPTIVE_EMBEDDINGS = 5   # per user
DEDUP_THRESHOLD = 0.08        # Euclidean distance below which is a duplicate
PRUNE_THRESHOLD = 0.65        # weighted similarity below which to prune
CORE_IMAGE_KEYS = frozenset({"timestamp"})


def temporal_decay_weight(timestamp: float, now: Optional[float] = None,
                          half_life: float = HALF_LIFE_SECONDS,
                          min_weight: float = MIN_WEIGHT) -> float:
    """Compute exponential decay weight for an embedding based on its age.

    Weight = max(2^(-age/half_life), min_weight)

    Args:
        timestamp: Unix timestamp (seconds) when embedding was created
        now: Current time (default: time.time())
        half_life: Decay half-life in seconds (default: 90 days)
        min_weight: Minimum weight floor (default: 0.3)

    Returns:
        Float weight in [min_weight, 1.0]
    """
    if now is None:
        now = time.time()
    age = max(0.0, now - timestamp)
    weight = math.pow(2, -age / half_life)
    return max(weight, min_weight)


def adaptive_key_ts(key: str) -> float:
    """Extract Unix timestamp from adaptive_<ts> key."""
    if key.startswith("adaptive_"):
        try:
            return float(key.split("_", 1)[1])
        except (ValueError, IndexError):
            pass
    return 0.0


def compute_weighted_similarity(query_embedding, user_data: dict,
                                now: Optional[float] = None) -> float:
    """Compute best weighted cosine similarity for a query against a user.

    Iterates over all embeddings (core image1-5 + adaptive_*) and applies
    temporal decay weight to each before selecting the maximum.

    Args:
        query_embedding: Query face embedding (list-like of floats)
        user_data: Firestore user document dict with embedding fields
        now: Current time for decay computation

    Returns:
        Best weighted similarity (float in [0, 1]), or 0.0 if no embeddings
    """
    if now is None:
        now = time.time()

    query = np.asarray(query_embedding, dtype=np.float64)
    best = 0.0

    for key in user_data:
        if key in CORE_IMAGE_KEYS:
            continue
        stored = user_data[key]
        if not isinstance(stored, list):
            continue

        raw_sim = cosine_similarity(query, stored)
        if key.startswith("adaptive_"):
            ts = adaptive_key_ts(key)
            weight = temporal_decay_weight(ts, now=now)
            weighted = raw_sim * weight
        else:
            weighted = raw_sim  # core embeddings weight = 1.0

        if weighted > best:
            best = weighted

    return best


def prune_adaptive_embeddings(db, user_id: str, user_data: dict,
                              query_embedding, now: Optional[float] = None) -> int:
    """Remove weak or stale adaptive embeddings from a user's document.

    Removes entries where weighted similarity to the query is below
    PRUNE_THRESHOLD. Core image1-5 fields are never removed.

    Args:
        db: Firestore client
        user_id: User document ID
        user_data: Current user document dict
        query_embedding: Reference embedding for similarity check
        now: Current timestamp

    Returns:
        Number of adaptive embeddings pruned (0 if none removed)
    """
    if now is None:
        now = time.time()

    query = np.asarray(query_embedding, dtype=np.float64)
    keys_to_remove = []

    for key, stored in user_data.items():
        if not key.startswith("adaptive_"):
            continue
        if not isinstance(stored, list):
            continue

        raw_sim = cosine_similarity(query, stored)
        ts = adaptive_key_ts(key)
        weight = temporal_decay_weight(ts, now=now)
        weighted = raw_sim * weight

        if weighted < PRUNE_THRESHOLD:
            keys_to_remove.append(key)

    if keys_to_remove:
        from firebase_admin import firestore
        updates = {key: firestore.DELETE_FIELD for key in keys_to_remove}
        db.collection("users").document(user_id).update(updates)
        logger.info("Pruned %d adaptive emb(s) for user=%s: %s",
                     len(keys_to_remove), user_id, keys_to_remove)

    return len(keys_to_remove)


def store_adaptive_embedding(db, user_id: str, embedding,
                             timestamp: Optional[float] = None) -> bool:
    """Store an adaptive embedding for a user with deduplication.

    Only stores if: fewer than MAX_ADAPTIVE_EMBEDDINGS exist and the new
    embedding is not a near-duplicate (Euclidean distance < DEDUP_THRESHOLD)
    of any existing adaptive embedding.

    Args:
        db: Firestore client
        user_id: User document ID
        embedding: Face embedding to store (list of floats)
        timestamp: Unix timestamp for the key (default: time.time())

    Returns:
        True if the embedding was stored, False if skipped (dup or at limit)
    """
    if timestamp is None:
        timestamp = time.time()

    user_snap = db.collection("users").document(user_id).get()
    if not user_snap.exists:
        logger.warning("store_adaptive: user=%s not found", user_id)
        return False

    user_data = user_snap.to_dict()

    adaptive = {}
    for key, val in user_data.items():
        if key.startswith("adaptive_") and isinstance(val, list):
            adaptive[key] = val

    if len(adaptive) >= MAX_ADAPTIVE_EMBEDDINGS:
        logger.debug("store_adaptive: user=%s already at max %d adaptive",
                      user_id, MAX_ADAPTIVE_EMBEDDINGS)
        return False

    new_arr = np.asarray(embedding, dtype=np.float64)
    for _, existing in adaptive.items():
        dist = euclidean_distance(new_arr, existing)
        if dist < DEDUP_THRESHOLD:
            logger.debug("store_adaptive: user=%s duplicate (dist=%.4f)",
                          user_id, dist)
            return False

    key = f"adaptive_{timestamp}"
    db.collection("users").document(user_id).update({key: embedding})
    logger.info("Stored adaptive embedding for user=%s as %s", user_id, key)
    return True
