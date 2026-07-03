"""Tests for face detection and embedding engine.

Requires mocking of insightface since the buffalo_l model pack
is 326MB and auto-downloads on first use.
"""

import os
import cv2
import numpy as np
import pytest
from unittest.mock import Mock, patch, MagicMock
from app.face import FaceEngine, ModelNotReadyError


@pytest.fixture
def mock_insightface_app():
    """Create a mock FaceAnalysis that returns fake detection results.

    The mock simulates a face detection returning a single face
    with a 512-dimensional embedding vector.
    """
    with patch("insightface.app.FaceAnalysis") as mock_face_analysis_class:
        mock_instance = MagicMock()
        mock_face_analysis_class.return_value = mock_instance

        mock_instance.prepare = MagicMock()

        # Mock face detection result
        mock_face = MagicMock()
        mock_face.embedding = np.random.default_rng(42).uniform(-1, 1, 512)
        mock_face.det_score = 0.95
        mock_face.bbox = [100, 100, 300, 300]
        mock_face.kps = np.array([
            [150, 150],
            [250, 150],
            [200, 200],
            [150, 250],
            [250, 250],
        ], dtype=np.float32)

        mock_instance.get = MagicMock(return_value=[mock_face])
        mock_instance.draw_on = MagicMock()

        yield mock_instance, mock_face_analysis_class


@pytest.fixture
def mock_insightface_no_face():
    """Mock that returns no faces detected."""
    with patch("insightface.app.FaceAnalysis") as mock_face_analysis_class:
        mock_instance = MagicMock()
        mock_face_analysis_class.return_value = mock_instance
        mock_instance.prepare = MagicMock()
        mock_instance.get = MagicMock(return_value=[])
        yield mock_instance, mock_face_analysis_class


@pytest.fixture
def sample_jpeg_bytes():
    """Generate a minimal valid JPEG image for testing.

    This is a 100x100 gradient image encoded as JPEG.
    """
    image = np.zeros((100, 100, 3), dtype=np.uint8)
    for i in range(100):
        image[i, :, :] = i * 2  # gradient
    success, buf = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, 85])
    if not success:
        pytest.skip("OpenCV JPEG encoding failed")
    return buf.tobytes()


class TestFaceEngineInitialization:
    def test_engine_initializes_with_buffalo_l(self, mock_insightface_app):
        mock_instance, mock_class = mock_insightface_app
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        mock_class.assert_called_once_with(name="buffalo_l")
        mock_instance.prepare.assert_called_once_with(ctx_id=0, det_size=(640, 640))
        assert engine._model is not None

    def test_engine_initializes_with_custom_det_size(self, mock_insightface_app):
        mock_instance, mock_class = mock_insightface_app
        engine = FaceEngine(model_name="buffalo_l", det_size=(320, 320))
        mock_instance.prepare.assert_called_once_with(ctx_id=0, det_size=(320, 320))

    def test_engine_uses_custom_providers(self, mock_insightface_app):
        mock_instance, mock_class = mock_insightface_app
        engine = FaceEngine(
            model_name="antelopev2",
            providers=["CPUExecutionProvider"],
        )
        mock_class.assert_called_once_with(
            name="antelopev2", providers=["CPUExecutionProvider"]
        )

    def test_engine_raises_on_prepare_failure(self, mock_insightface_app):
        mock_instance, mock_class = mock_insightface_app
        mock_instance.prepare.side_effect = RuntimeError("Model load failed")
        with pytest.raises(RuntimeError, match="Model load failed"):
            FaceEngine(model_name="buffalo_l")


class TestGetEmbedding:
    def test_returns_512_dim_embedding(self, mock_insightface_app, sample_jpeg_bytes):
        mock_instance, _ = mock_insightface_app
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        embedding = engine.get_embedding(sample_jpeg_bytes)
        assert embedding is not None
        assert len(embedding) == 512
        assert all(isinstance(x, float) for x in embedding)

    def test_returns_normalized_embedding(self, mock_insightface_app, sample_jpeg_bytes):
        mock_instance, _ = mock_insightface_app
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        embedding = engine.get_embedding(sample_jpeg_bytes)
        assert embedding is not None
        norm = np.linalg.norm(embedding)
        assert norm == pytest.approx(1.0, abs=1e-5)

    def test_returns_none_for_no_face(self, mock_insightface_no_face, sample_jpeg_bytes):
        mock_instance, _ = mock_insightface_no_face
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        embedding = engine.get_embedding(sample_jpeg_bytes)
        assert embedding is None

    def test_returns_none_for_corrupted_bytes(self, mock_insightface_app):
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        corrupted = b"\x00\xff\xfe\xed" * 100  # garbage
        embedding = engine.get_embedding(corrupted)
        assert embedding is None

    def test_returns_none_for_empty_bytes(self, mock_insightface_app):
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        embedding = engine.get_embedding(b"")
        assert embedding is None

    def test_detection_size_applied(self, mock_insightface_app, sample_jpeg_bytes):
        mock_instance, _ = mock_insightface_app
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        engine.get_embedding(sample_jpeg_bytes)
        # Verify the image was decoded and passed to model
        call_args = mock_instance.get.call_args
        assert call_args is not None
        input_image = call_args[0][0]
        assert input_image.shape is not None


class TestGetEmbeddingBatch:
    """Batch embedding extraction."""

    def test_batch_all_successful(self, mock_insightface_app, sample_jpeg_bytes):
        mock_instance, _ = mock_insightface_app
        # Set up mock to return face for each call
        mock_face = MagicMock()
        mock_face.embedding = np.random.default_rng(42).uniform(-1, 1, 512)
        mock_instance.get = MagicMock(return_value=[mock_face])

        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        images = [sample_jpeg_bytes] * 3
        results = engine.get_embedding_batch(images)
        assert len(results) == 3
        assert all(r is not None for r in results)
        assert all(len(r) == 512 for r in results)

    def test_batch_some_fail(self, mock_insightface_no_face, sample_jpeg_bytes):
        """When no face detected, that slot should be None."""
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        images = [sample_jpeg_bytes] * 3
        results = engine.get_embedding_batch(images)
        assert len(results) == 3
        assert all(r is None for r in results)


class TestFaceDetection:
    """Tests for the raw face detection method."""

    def test_detect_returns_face_count(self, mock_insightface_app, sample_jpeg_bytes):
        mock_instance, _ = mock_insightface_app
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        faces = engine.detect(sample_jpeg_bytes)
        assert len(faces) == 1
        assert "bbox" in faces[0]
        assert "det_score" in faces[0]
        assert "landmarks" in faces[0]

    def test_detect_no_face_returns_empty(self, mock_insightface_no_face, sample_jpeg_bytes):
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        faces = engine.detect(sample_jpeg_bytes)
        assert faces == []

    def test_detect_corrupted_returns_empty(self, mock_insightface_app):
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        faces = engine.detect(b"garbage data that is not an image" * 100)
        assert faces == []


class TestModelNotReady:
    def test_get_embedding_before_initialize_raises(self):
        engine = FaceEngine.__new__(FaceEngine)
        engine._model = None
        with pytest.raises(ModelNotReadyError, match="not initialized"):
            engine.get_embedding(b"test")

    def test_detect_before_initialize_raises(self):
        engine = FaceEngine.__new__(FaceEngine)
        engine._model = None
        with pytest.raises(ModelNotReadyError, match="not initialized"):
            engine.detect(b"test")


class TestIntegrationWithRealModel:
    """These tests require the buffalo_l model to be downloaded.

    Skip automatically if model is not available.
    """

    @pytest.fixture
    def real_engine(self):
        try:
            engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
            return engine
        except Exception as e:
            pytest.skip(f"Model not available: {e}")

    @pytest.fixture
    def test_image_bytes(self):
        """Find a real (unencrypted) test image from test-images/ dir."""
        project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..")
        )
        test_image_dir = os.path.join(project_root, "test-images")
        if not os.path.isdir(test_image_dir):
            pytest.skip("test-images/ directory not found")
        # Pick the first non-encrypted JPEG (encrypted images won't decode)
        for f in sorted(os.listdir(test_image_dir)):
            if f.lower().endswith((".jpg", ".jpeg")) and not f.startswith("encrypted"):
                path = os.path.join(test_image_dir, f)
                with open(path, "rb") as fp:
                    return fp.read()
        pytest.skip("No valid test images found")

    def test_real_image_produces_embedding(self, real_engine, test_image_bytes):
        embedding = real_engine.get_embedding(test_image_bytes)
        assert embedding is not None
        assert len(embedding) == 512

    def test_real_embedding_is_normalized(self, real_engine, test_image_bytes):
        embedding = real_engine.get_embedding(test_image_bytes)
        assert embedding is not None
        norm = np.linalg.norm(embedding)
        assert norm == pytest.approx(1.0, abs=1e-5)

    def test_same_image_same_embedding(self, real_engine, test_image_bytes):
        """Deterministic: same image should give same embedding."""
        emb1 = real_engine.get_embedding(test_image_bytes)
        emb2 = real_engine.get_embedding(test_image_bytes)
        assert emb1 is not None and emb2 is not None
        diff = np.linalg.norm(np.array(emb1) - np.array(emb2))
        assert diff < 0.001, f"Embeddings diverged: diff={diff}"

    def test_different_images_different_embeddings(self, real_engine, test_image_bytes):
        """Two different images should produce different embeddings."""
        # Create a modified image by flipping
        nparr = np.frombuffer(test_image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            pytest.skip("Could not decode test image")
        flipped = cv2.flip(img, 1)
        success, buf = cv2.imencode(".jpg", flipped, [cv2.IMWRITE_JPEG_QUALITY, 85])
        if not success:
            pytest.skip("Could not encode flipped image")
        flipped_bytes = buf.tobytes()

        emb1 = real_engine.get_embedding(test_image_bytes)
        emb2 = real_engine.get_embedding(flipped_bytes)
        assert emb1 is not None and emb2 is not None
        # They should be different (but could still match the same person)
        # We just assert they're not identical
        diff = np.linalg.norm(np.array(emb1) - np.array(emb2))
        assert diff > 0.0
