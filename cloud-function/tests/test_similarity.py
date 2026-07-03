"""Tests for face similarity and distance functions.

Cosine similarity must produce:
  - 1.0 for identical vectors
  - 0.0 for orthogonal vectors
  - -1.0 for opposite vectors

Euclidean distance must produce:
  - 0.0 for identical vectors
  - Positive values for different vectors
"""

import math
import numpy as np
import pytest
from app.similarity import (
    cosine_similarity,
    euclidean_distance,
    is_duplicate,
    normalize_embedding,
    EMBEDDING_SIMILARITY_THRESHOLD,
)


class TestCosineSimilarity:
    def test_identical_vectors(self):
        v = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert cosine_similarity(v, v) == pytest.approx(1.0, abs=1e-10)

    def test_identical_vectors_random(self):
        rng = np.random.default_rng(42)
        v = rng.uniform(-1, 1, 128).tolist()
        assert cosine_similarity(v, v) == pytest.approx(1.0, abs=1e-10)

    def test_orthogonal_vectors(self):
        """Orthogonal in 2D: [1,0] and [0,1]"""
        assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0, abs=1e-10)

    def test_opposite_vectors(self):
        assert cosine_similarity([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0, abs=1e-10)

    def test_parallel_scaled(self):
        """Scaling shouldn't affect cosine similarity."""
        assert cosine_similarity([2.0, 4.0], [1.0, 2.0]) == pytest.approx(1.0, abs=1e-10)

    def test_known_angle_45(self):
        """[1,0] and [1,1]: angle = 45°, cos = 0.7071..."""
        sim = cosine_similarity([1.0, 0.0], [1.0, 1.0])
        assert sim == pytest.approx(math.sqrt(2) / 2, abs=1e-6)

    def test_symmetric(self):
        """cosine_similarity(a, b) == cosine_similarity(b, a)."""
        a = [1.0, 2.0, 3.0]
        b = [4.0, -5.0, 6.0]
        assert cosine_similarity(a, b) == pytest.approx(cosine_similarity(b, a), abs=1e-10)

    def test_zero_vector(self):
        """Zero vector has no direction; dot product should be 0."""
        assert cosine_similarity([0.0, 0.0], [1.0, 0.0]) == pytest.approx(0.0, abs=1e-10)

    def test_embedding_dimensionality(self):
        """InsightFace produces 512-dim embeddings."""
        rng = np.random.default_rng(42)
        a = rng.uniform(-1, 1, 512).tolist()
        b = rng.uniform(-1, 1, 512).tolist()
        sim = cosine_similarity(a, b)
        assert -1.0 <= sim <= 1.0

    def test_negative_values(self):
        a = [1.0, -2.0, 3.0, -4.0]
        b = [-1.0, 2.0, -3.0, 4.0]
        sim = cosine_similarity(a, b)
        assert -1.0 <= sim <= 1.0

    def test_numpy_input(self):
        """Should accept numpy arrays too."""
        a = np.array([1.0, 2.0, 3.0, 4.0])
        b = np.array([5.0, 6.0, 7.0, 8.0])
        result = cosine_similarity(a, b)
        assert isinstance(result, float)
        assert -1.0 <= result <= 1.0


class TestEuclideanDistance:
    def test_identical_vectors(self):
        v = [1.0, 2.0, 3.0]
        assert euclidean_distance(v, v) == pytest.approx(0.0, abs=1e-10)

    def test_known_distance_2d(self):
        """[0,0] to [3,4] = 5."""
        assert euclidean_distance([0.0, 0.0], [3.0, 4.0]) == pytest.approx(5.0, abs=1e-10)

    def test_symmetric(self):
        a = [1.0, 2.0, 3.0]
        b = [4.0, 5.0, 6.0]
        assert euclidean_distance(a, b) == pytest.approx(euclidean_distance(b, a), abs=1e-10)

    def test_non_negative(self):
        """Distance must never be negative."""
        rng = np.random.default_rng(42)
        for _ in range(100):
            a = rng.uniform(-10, 10, 128).tolist()
            b = rng.uniform(-10, 10, 128).tolist()
            assert euclidean_distance(a, b) >= 0.0

    def test_zero_vector_distance_from_origin(self):
        v = [3.0, 4.0, 0.0, 12.0]
        assert euclidean_distance([0.0] * 4, v) == pytest.approx(13.0, abs=1e-10)

    def test_embedding_dimensionality(self):
        """Real embedding distance is typically 0-2 range."""
        rng = np.random.default_rng(42)
        a = rng.uniform(-1, 1, 512).tolist()
        b = rng.uniform(-1, 1, 512).tolist()
        dist = euclidean_distance(a, b)
        # 512-dim random vectors should have distance ~ sqrt(512 * (2/3)^2 * 2) ≈ 15.1
        assert 0.0 < dist < 50.0


class TestNormalizeEmbedding:
    def test_normalized_vector_has_unit_length(self):
        rng = np.random.default_rng(42)
        v = rng.uniform(-1, 1, 128).tolist()
        nv = normalize_embedding(v)
        norm = math.sqrt(sum(x * x for x in nv))
        assert norm == pytest.approx(1.0, abs=1e-6)

    def test_normalized_preserves_direction(self):
        """Normalized vector should point same direction."""
        v = [3.0, 4.0]
        nv = normalize_embedding(v)
        assert nv[0] == pytest.approx(0.6, abs=1e-6)
        assert nv[1] == pytest.approx(0.8, abs=1e-6)

    def test_normalize_zero_vector(self):
        with pytest.raises(ValueError, match="(zero|null|cannot normalize)"):
            normalize_embedding([0.0, 0.0, 0.0])


class TestIsDuplicate:
    def test_identical_embedding_returns_true(self):
        v = [1.0, 2.0, 3.0]
        assert is_duplicate(v, [v]) is True

    def test_different_embeddings_return_false(self):
        rng = np.random.default_rng(42)
        a = rng.uniform(-1, 1, 128).tolist()
        b = rng.uniform(-1, 1, 128).tolist()
        assert is_duplicate(a, [b]) is False

    def test_threshold_exact(self):
        """Embeddings at exactly threshold distance should be duplicate."""
        v = [1.0, 0.0, 0.0]
        # Create a point at exactly threshold distance
        threshold = EMBEDDING_SIMILARITY_THRESHOLD
        close = [1.0 + threshold * 0.99, 0.0, 0.0]  # slightly less than threshold away
        assert is_duplicate(v, [close]) is True
        far = [1.0 + threshold * 1.01, 0.0, 0.0]  # slightly more
        assert is_duplicate(v, [far]) is False

    def test_multiple_existing_one_match(self):
        """Should return True if any existing embedding is a dupe."""
        rng = np.random.default_rng(42)
        existing = rng.uniform(-1, 1, (10, 128)).tolist()
        # One of the existing should match itself
        assert is_duplicate(existing[5], existing) is True

    def test_empty_existing_list(self):
        """No existing embeddings = never duplicate."""
        v = [1.0, 2.0, 3.0]
        assert is_duplicate(v, []) is False

    def test_handles_single_embedding(self):
        """Existing list with single element."""
        v = [1.0, 0.0, 0.0]
        assert is_duplicate(v, [v]) is True
        other = [0.0, 1.0, 0.0]
        assert is_duplicate(other, [v]) is False

    def test_handles_large_existing_list(self):
        """Performance sanity: many existing embeddings."""
        rng = np.random.default_rng(42)
        existing = rng.uniform(-1, 1, (100, 512)).tolist()
        query = rng.uniform(-1, 1, 512).tolist()
        result = is_duplicate(query, existing)
        assert isinstance(result, bool)
