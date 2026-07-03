"""Face embedding similarity and distance utilities.

Provides cosine similarity, Euclidean distance, and duplicate detection
for face embedding vectors (typically 512-dim from InsightFace).
"""

import numpy as np

# Threshold: max Euclidean distance to consider two embeddings duplicates.
# Based on observed distances for InsightFace buffalo_l embeddings
# of the same person under different conditions (lighting, angle).
EMBEDDING_SIMILARITY_THRESHOLD = 0.08


def cosine_similarity(emb1, emb2) -> float:
    """Compute cosine similarity between two embedding vectors.

    Returns a value in [-1, 1] where:
        - 1.0 = identical direction
        - 0.0 = orthogonal
        - -1.0 = opposite direction

    Args:
        emb1: First embedding (list-like of floats)
        emb2: Second embedding (list-like of floats)

    Returns:
        Cosine similarity as a float
    """
    a = np.asarray(emb1, dtype=np.float64)
    b = np.asarray(emb2, dtype=np.float64)

    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return float(np.dot(a, b) / (norm_a * norm_b))


def euclidean_distance(emb1, emb2) -> float:
    """Compute Euclidean distance between two embedding vectors.

    Args:
        emb1: First embedding (list-like of floats)
        emb2: Second embedding (list-like of floats)

    Returns:
        Non-negative Euclidean distance
    """
    a = np.asarray(emb1, dtype=np.float64)
    b = np.asarray(emb2, dtype=np.float64)
    return float(np.linalg.norm(a - b))


def normalize_embedding(embedding):
    """Normalize an embedding vector to unit length.

    Args:
        embedding: Input vector (list-like of floats)

    Returns:
        Normalized vector as a list

    Raises:
        ValueError: If the input vector is all zeros
    """
    arr = np.asarray(embedding, dtype=np.float64)
    norm = np.linalg.norm(arr)
    if norm == 0:
        raise ValueError("cannot normalize a zero vector")
    return (arr / norm).tolist()


def is_duplicate(new_embedding, existing_embeddings) -> bool:
    """Check if a new embedding is too similar to any existing ones.

    Uses Euclidean distance with EMBEDDING_SIMILARITY_THRESHOLD
    to prevent storing redundant adaptive embeddings.

    Args:
        new_embedding: Candidate embedding (list of floats)
        existing_embeddings: List of existing embeddings to compare against

    Returns:
        True if new_embedding is within threshold of any existing embedding
    """
    if not existing_embeddings:
        return False

    new_arr = np.asarray(new_embedding, dtype=np.float64)

    for existing in existing_embeddings:
        existing_arr = np.asarray(existing, dtype=np.float64)
        distance = float(np.linalg.norm(new_arr - existing_arr))
        if distance < EMBEDDING_SIMILARITY_THRESHOLD:
            return True

    return False
