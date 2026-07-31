"""Tests for continuous learning engine: temporal decay, weighted similarity,
adaptive embedding storage, and pruning.
"""

import math
import time
import numpy as np
import pytest
from unittest.mock import MagicMock

from app.learning import (
    temporal_decay_weight,
    adaptive_key_ts,
    compute_weighted_similarity,
    store_adaptive_embedding,
    prune_adaptive_embeddings,
    HALF_LIFE_SECONDS,
    MIN_WEIGHT,
    MAX_ADAPTIVE_EMBEDDINGS,
    DEDUP_THRESHOLD,
    PRUNE_THRESHOLD,
)


# ── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def embedding():
    rng = np.random.default_rng(42)
    emb = rng.normal(0, 1, 512)
    return (emb / np.linalg.norm(emb)).tolist()


@pytest.fixture
def similar_embedding(embedding):
    arr = np.array(embedding) + np.random.default_rng(99).normal(0, 0.01, 512)
    return (arr / np.linalg.norm(arr)).tolist()


@pytest.fixture
def different_embedding():
    rng = np.random.default_rng(77)
    emb = rng.normal(0, 1, 512)
    return (emb / np.linalg.norm(emb)).tolist()


@pytest.fixture
def user_data_with_core(embedding):
    return {
        "image1": embedding,
        "image2": embedding,
        "image3": embedding,
        "image4": embedding,
        "image5": embedding,
        "timestamp": 1234567890,
    }


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

            def _update(data):
                if doc_id in col._storage:
                    col._storage[doc_id].update(data)
                else:
                    col._storage[doc_id] = data

            doc.get = _get
            doc.set = _set
            doc.update = _update
            return doc

        def _stream():
            return [
                MagicMock(id=did, to_dict=MagicMock(return_value=data))
                for did, data in col._storage.items()
            ]

        col.document = _document
        col.stream = _stream
        return col

    db.collection = _collection
    return db


# ── Temporal Decay Tests ────────────────────────────────────────────────

class TestTemporalDecayWeight:
    def test_brand_new_embedding_weight_is_1(self):
        now = time.time()
        w = temporal_decay_weight(timestamp=now, now=now)
        assert w == 1.0

    def test_exactly_one_half_life(self):
        now = time.time()
        past = now - HALF_LIFE_SECONDS
        w = temporal_decay_weight(timestamp=past, now=now)
        assert math.isclose(w, 0.5, rel_tol=0.01)

    def test_exactly_two_half_lives(self):
        now = time.time()
        past = now - 2 * HALF_LIFE_SECONDS
        w = temporal_decay_weight(timestamp=past, now=now)
        assert w == MIN_WEIGHT

    def test_very_old_hits_min_weight(self):
        now = time.time()
        past = now - 10 * HALF_LIFE_SECONDS
        w = temporal_decay_weight(timestamp=past, now=now)
        assert w == MIN_WEIGHT

    def test_use_now_default(self):
        w = temporal_decay_weight(timestamp=time.time())
        assert w >= 0.99

    def test_monotonic_decay(self):
        now = time.time()
        w0 = temporal_decay_weight(timestamp=now - 0, now=now)
        w1 = temporal_decay_weight(timestamp=now - 100_000, now=now)
        w2 = temporal_decay_weight(timestamp=now - 1_000_000, now=now)
        assert w0 >= w1 >= w2


# ── Adaptive Key Parsing Tests ──────────────────────────────────────────

class TestAdaptiveKeyTs:
    def test_valid_key(self):
        assert adaptive_key_ts("adaptive_1719000000.0") == 1719000000.0

    def test_core_key_returns_zero(self):
        assert adaptive_key_ts("image1") == 0.0

    def test_invalid_suffix_returns_zero(self):
        assert adaptive_key_ts("adaptive_abc") == 0.0

    def test_no_suffix_returns_zero(self):
        assert adaptive_key_ts("adaptive_") == 0.0


# ── Weighted Similarity Tests ───────────────────────────────────────────

class TestComputeWeightedSimilarity:
    def test_core_embedding_match(self, embedding, user_data_with_core):
        sim = compute_weighted_similarity(embedding, user_data_with_core)
        assert math.isclose(sim, 1.0, abs_tol=0.001)

    def test_adaptive_embedding_with_decay(self, embedding):
        now = time.time()
        old_ts = now - HALF_LIFE_SECONDS
        user_data = {f"adaptive_{old_ts}": embedding}
        sim = compute_weighted_similarity(embedding, user_data, now=now)
        assert math.isclose(sim, 0.5, rel_tol=0.01)

    def test_adaptive_below_weight_floor(self, embedding):
        now = time.time()
        very_old_ts = now - 10 * HALF_LIFE_SECONDS
        user_data = {f"adaptive_{very_old_ts}": embedding}
        sim = compute_weighted_similarity(embedding, user_data, now=now)
        assert math.isclose(sim, MIN_WEIGHT, rel_tol=0.01)

    def test_empty_user_data(self, embedding):
        sim = compute_weighted_similarity(embedding, {})
        assert sim == 0.0

    def test_only_metadata_field(self, embedding):
        sim = compute_weighted_similarity(embedding, {"timestamp": 123})
        assert sim == 0.0

    def test_skips_non_list_values(self, embedding):
        user_data = {
            "image1": [1.0] * 512,
            "adaptive_1": "not_a_list",
            "adaptive_2": None,
        }
        sim = compute_weighted_similarity(embedding, user_data)
        assert sim >= 0.0

    def test_picks_best_among_multiple(self, embedding, similar_embedding,
                                        different_embedding):
        now = time.time()
        user_data = {
            "image1": different_embedding,
            f"adaptive_{now - HALF_LIFE_SECONDS}": embedding,
        }
        sim = compute_weighted_similarity(embedding, user_data, now=now)
        assert math.isclose(sim, 0.5, rel_tol=0.01)


# ── Store Adaptive Embedding Tests ──────────────────────────────────────

class TestStoreAdaptiveEmbedding:
    def test_stores_new_embedding(self, mock_firestore, embedding):
        mock_firestore.collection("users").document("alice").set({
            "image1": embedding,
            "image2": embedding,
            "image3": embedding,
            "image4": embedding,
            "image5": embedding,
        })
        result = store_adaptive_embedding(mock_firestore, "alice", embedding)
        assert result is True
        stored = mock_firestore._storage["users"]["alice"]
        adaptive_keys = [k for k in stored if k.startswith("adaptive_")]
        assert len(adaptive_keys) == 1

    def test_skips_duplicate_embedding(self, mock_firestore, embedding):
        mock_firestore.collection("users").document("bob").set({
            "image1": embedding,
            "image2": embedding,
            "image3": embedding,
            "image4": embedding,
            "image5": embedding,
        })
        store_adaptive_embedding(mock_firestore, "bob", embedding)
        result = store_adaptive_embedding(mock_firestore, "bob", embedding)
        assert result is False

    def test_at_max_capacity(self, mock_firestore, embedding, different_embedding):
        base = {
            "image1": embedding,
            "image2": embedding,
            "image3": embedding,
            "image4": embedding,
            "image5": embedding,
        }
        for i in range(MAX_ADAPTIVE_EMBEDDINGS):
            rng = np.random.default_rng(i + 100)
            emb = rng.normal(0, 1, 512)
            emb = (emb / np.linalg.norm(emb)).tolist()
            base[f"adaptive_{1000000 + i}"] = emb

        mock_firestore.collection("users").document("charlie").set(base)
        result = store_adaptive_embedding(
            mock_firestore, "charlie", different_embedding
        )
        assert result is False

    def test_user_not_found(self, mock_firestore, embedding):
        result = store_adaptive_embedding(mock_firestore, "ghost", embedding)
        assert result is False


# ── Prune Adaptive Embeddings Tests ─────────────────────────────────────

class TestPruneAdaptiveEmbeddings:
    def test_prunes_weak_embeddings(self, mock_firestore, embedding,
                                     different_embedding):
        now = time.time()
        very_old_ts = now - 10 * HALF_LIFE_SECONDS
        user_data = {
            "image1": embedding,
            "image2": embedding,
            "image3": embedding,
            "image4": embedding,
            "image5": embedding,
            f"adaptive_{very_old_ts}": embedding,
        }
        mock_firestore.collection("users").document("dave").set(user_data)

        pruned = prune_adaptive_embeddings(
            mock_firestore, "dave", user_data, embedding, now=now
        )
        assert pruned >= 1

    def test_keeps_strong_embeddings(self, mock_firestore, embedding):
        now = time.time()
        recent_ts = now
        user_data = {
            "image1": embedding,
            f"adaptive_{recent_ts}": embedding,
        }
        mock_firestore.collection("users").document("eve").set(user_data)

        pruned = prune_adaptive_embeddings(
            mock_firestore, "eve", user_data, embedding, now=now
        )
        assert pruned == 0

    def test_no_adaptive_embeddings(self, mock_firestore, embedding):
        user_data = {
            "image1": embedding,
            "image2": embedding,
        }
        mock_firestore.collection("users").document("frank").set(user_data)

        pruned = prune_adaptive_embeddings(
            mock_firestore, "frank", user_data, embedding
        )
        assert pruned == 0

    def test_never_removes_core_embeddings(self, mock_firestore, embedding,
                                            different_embedding):
        now = time.time()
        very_old_ts = now - 10 * HALF_LIFE_SECONDS
        user_data = {
            "image1": embedding,
            "image2": embedding,
            "image3": embedding,
            "image4": embedding,
            "image5": embedding,
            f"adaptive_{very_old_ts}": embedding,
        }
        mock_firestore.collection("users").document("grace").set(user_data)

        prune_adaptive_embeddings(
            mock_firestore, "grace", user_data, embedding, now=now
        )
        stored = mock_firestore._storage["users"]["grace"]
        for key in ("image1", "image2", "image3", "image4", "image5"):
            assert key in stored
