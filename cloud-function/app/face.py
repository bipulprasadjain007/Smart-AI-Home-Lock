"""Face detection, alignment, and embedding extraction engine.

Uses InsightFace with buffalo_l model pack for:
  - Face detection (SCRFD-10GF)
  - Face alignment (2d106 + 3d68 landmarks)
  - Face recognition (ResNet50@WebFace600K → 512-dim embeddings)

On Cloud Functions, models are downloaded from GCS on cold start
to avoid exceeding deployment size limits.
"""

from __future__ import annotations

import logging
import os
import shutil
from typing import List, Optional

import cv2
import numpy as np

logger = logging.getLogger(__name__)

MODEL_FILES = [
    "det_10g.onnx",
    "w600k_r50.onnx",
    "2d106det.onnx",
]


class ModelNotReadyError(RuntimeError):
    """Raised when a face operation is attempted before model initialization."""


class FaceEngine:
    """Face detection + alignment + embedding extraction engine.

    Wraps InsightFace's FaceAnalysis to provide a clean interface
    for the Smart AI Home Lock pipeline.

    Usage:
        engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))
        embedding = engine.get_embedding(image_bytes)
        if embedding is not None:
            # match against stored embeddings
    """

    def __init__(
        self,
        model_name: str = "buffalo_l",
        det_size: tuple = (640, 640),
        providers: Optional[list] = None,
        gcs_bucket: Optional[object] = None,
        model_root: str = "/tmp/.insightface",
    ):
        """Initialize the face engine with a specific model pack.

        On Cloud Functions, models are downloaded from GCS.
        Locally, uses ~/.insightface/models/ if models already exist there.

        Args:
            model_name: InsightFace model pack name (default: "buffalo_l")
            det_size: Detection input size as (width, height)
            providers: ONNX Runtime providers (default: auto-detect)
            gcs_bucket: Google Cloud Storage Bucket for model download
            model_root: Local directory for model storage (/tmp/.insightface)

        Raises:
            RuntimeError: If model initialization or download fails
        """
        self._model = None
        self._det_size = det_size
        self._model_name = model_name
        self._model_root = model_root

        self._ensure_models(gcs_bucket)
        self._initialize_model(providers)

    def _ensure_models(self, gcs_bucket: Optional[object] = None) -> None:
        """Ensure local ONNX model files exist, downloading from GCS if needed.

        Args:
            gcs_bucket: Google Cloud Storage Bucket (or None for local dev)
        """
        local_model_dir = os.path.join(self._model_root, self._model_name)

        # Check if models already exist locally
        all_present = all(
            os.path.isfile(os.path.join(local_model_dir, f))
            for f in MODEL_FILES
        )

        if all_present:
            logger.info("Using cached models at %s", local_model_dir)
            return

        # Try GCS download
        if gcs_bucket is not None:
            os.makedirs(local_model_dir, exist_ok=True)
            for model_file in MODEL_FILES:
                gcs_path = f"models/{self._model_name}/{model_file}"
                local_path = os.path.join(local_model_dir, model_file)
                if not os.path.isfile(local_path):
                    blob = gcs_bucket.blob(gcs_path)
                    if blob.exists():
                        logger.info("Downloading %s from GCS...", model_file)
                        blob.download_to_filename(local_path)
                    else:
                        logger.warning("Model %s not found in GCS", gcs_path)
            return

        # Local dev: models should be in ~/.insightface/models/
        logger.info(
            "No GCS bucket configured; InsightFace will auto-download models "
            "from internet if needed"
        )

    def _initialize_model(self, providers: Optional[list] = None) -> None:
        """Download (if needed) and initialize the InsightFace model.

        Args:
            providers: ONNX Runtime providers list

        Raises:
            RuntimeError: On initialization failure
        """
        try:
            from insightface.app import FaceAnalysis

            kwargs = {"name": self._model_name}
            if providers is not None:
                kwargs["providers"] = providers

            kwargs["root"] = self._model_root

            self._model = FaceAnalysis(**kwargs)
            self._model.prepare(ctx_id=0, det_size=self._det_size)
            logger.info(
                "FaceEngine initialized with model='%s', det_size=%s",
                self._model_name,
                self._det_size,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize InsightFace model: {e}") from e

    def _check_ready(self) -> None:
        """Verify engine is initialized before use."""
        if self._model is None:
            raise ModelNotReadyError(
                "FaceEngine not initialized. Call FaceEngine() first."
            )

    def _decode_image(self, image_bytes: bytes) -> Optional[np.ndarray]:
        """Decode raw image bytes into an OpenCV BGR array.

        Args:
            image_bytes: Raw JPEG/PNG bytes

        Returns:
            Decoded BGR image, or None on failure
        """
        try:
            nparr = np.frombuffer(image_bytes, np.uint8)
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            return image
        except Exception as e:
            logger.warning("Image decode failed: %s", e)
            return None

    def get_embedding(self, image_bytes: bytes) -> Optional[List[float]]:
        """Extract a face embedding from an image.

        Returns the embedding of the highest-confidence face found,
        or None if no face is detected or the image is corrupted.

        The embedding is L2-normalized to unit length.

        Args:
            image_bytes: Raw image bytes (JPEG, PNG)

        Returns:
            512-element embedding vector, or None
        """
        self._check_ready()

        image = self._decode_image(image_bytes)
        if image is None:
            return None

        try:
            faces = self._model.get(image)
            if len(faces) == 0:
                logger.debug("No face detected in image")
                return None

            embedding = faces[0].embedding.tolist()
            # L2-normalize
            norm = np.linalg.norm(embedding)
            if norm > 0:
                embedding = (np.array(embedding) / norm).tolist()

            logger.debug("Extracted embedding, dim=%d, norm=%.4f", len(embedding), norm)
            return embedding
        except Exception as e:
            logger.error("Embedding extraction failed: %s", e)
            return None

    def get_embedding_batch(
        self, images_bytes: List[bytes]
    ) -> List[Optional[List[float]]]:
        """Extract embeddings from multiple images.

        Processes each image independently and returns results
        in the same order. Failed images yield None.

        Args:
            images_bytes: List of raw image byte arrays

        Returns:
            List of embeddings (or None for failed images)
        """
        return [self.get_embedding(img_bytes) for img_bytes in images_bytes]

    def detect(self, image_bytes: bytes) -> List[dict]:
        """Detect all faces in an image with their bounding boxes and scores.

        Args:
            image_bytes: Raw image bytes (JPEG, PNG)

        Returns:
            List of dicts with keys:
                - 'bbox': [x1, y1, x2, y2] bounding box
                - 'det_score': Detection confidence (0-1)
                - 'landmarks': 5 keypoints [[x,y], ...]
            Empty list if no faces detected or image is corrupted.
        """
        self._check_ready()

        image = self._decode_image(image_bytes)
        if image is None:
            return []

        try:
            faces = self._model.get(image)
            results = []
            for face in faces:
                results.append({
                    "bbox": face.bbox.tolist() if hasattr(face.bbox, "tolist") else face.bbox,
                    "det_score": float(face.det_score),
                    "landmarks": face.kps.tolist() if hasattr(face.kps, "tolist") else face.kps,
                })
            return results
        except Exception as e:
            logger.error("Face detection failed: %s", e)
            return []
