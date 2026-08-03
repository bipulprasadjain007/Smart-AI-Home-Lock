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
import hashlib
import json
import os
import re
import shutil
import tempfile
from typing import Any, List, Mapping, Optional

import cv2
import numpy as np

from app.similarity import validate_embedding

logger = logging.getLogger(__name__)

MODEL_FILES = [
    "det_10g.onnx",
    "w600k_r50.onnx",
    "2d106det.onnx",
]
SHA256_RE = r"^[0-9a-fA-F]{64}$"


class ModelNotReadyError(RuntimeError):
    """Raised when a face operation is attempted before model initialization."""


class ModelSupplyChainError(RuntimeError):
    """Raised when production model provenance or artifacts cannot be verified."""


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
        model_manifest: Any = None,
        production: bool = False,
        allow_internet_fallback: Optional[bool] = None,
        model_files: Optional[list[str]] = None,
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
        self._production = bool(production)
        self._allow_internet_fallback = (
            not self._production
            if allow_internet_fallback is None
            else bool(allow_internet_fallback)
        )
        self._model_files = tuple(model_files or MODEL_FILES)
        self._model_manifest = self._normalize_manifest(model_manifest)

        self._ensure_models(gcs_bucket)
        self._initialize_model(providers)

    def _normalize_manifest(self, value: Any) -> dict[str, dict[str, Any]] | None:
        """Normalize a manifest without accepting ambiguous artifact metadata."""

        if value is None or value == "":
            if self._production:
                raise ModelSupplyChainError(
                    "production model manifest is required"
                )
            return None

        if isinstance(value, str):
            try:
                if value.lstrip().startswith(("{", "[")):
                    value = json.loads(value)
                else:
                    with open(value, "r", encoding="utf-8") as manifest_file:
                        value = json.load(manifest_file)
            except (OSError, TypeError, ValueError) as error:
                raise ModelSupplyChainError("invalid model manifest") from error

        if not isinstance(value, Mapping):
            raise ModelSupplyChainError("model manifest must be an object")
        manifest_model = value.get("model_name")
        if manifest_model is not None and manifest_model != self._model_name:
            raise ModelSupplyChainError("model manifest name mismatch")

        entries = value.get("files", value.get("artifacts"))
        if entries is None:
            # Also accept a direct filename -> metadata mapping.
            entries = value
        normalized: dict[str, dict[str, Any]] = {}
        if isinstance(entries, list):
            iterable = []
            for entry in entries:
                if not isinstance(entry, Mapping):
                    raise ModelSupplyChainError("model manifest file entry is invalid")
                name = entry.get("name", entry.get("path", entry.get("file")))
                iterable.append((name, entry))
        elif isinstance(entries, Mapping):
            iterable = list(entries.items())
        else:
            raise ModelSupplyChainError("model manifest files must be an object or list")

        for name, metadata in iterable:
            if not isinstance(name, str) or not name or os.path.basename(name) != name:
                raise ModelSupplyChainError("model manifest contains an unsafe filename")
            if not isinstance(metadata, Mapping):
                raise ModelSupplyChainError("model manifest metadata is invalid")
            size = metadata.get("size", metadata.get("size_bytes", metadata.get("bytes")))
            digest = metadata.get("sha256", metadata.get("sha256_hex"))
            try:
                size = int(size)
            except (TypeError, ValueError) as error:
                raise ModelSupplyChainError("model manifest size is invalid") from error
            if size <= 0 or not isinstance(digest, str):
                raise ModelSupplyChainError("model manifest metadata is incomplete")
            if not re.fullmatch(SHA256_RE, digest):
                raise ModelSupplyChainError("model manifest sha256 is invalid")
            if name in normalized:
                raise ModelSupplyChainError("duplicate model manifest filename")
            normalized[name] = {"size": size, "sha256": digest.lower()}

        expected = set(self._model_files)
        if not normalized or not expected.issubset(normalized):
            raise ModelSupplyChainError("model manifest is missing expected files")
        # A production manifest is authoritative: an unlisted model file must
        # not silently enter the cache or be downloaded by InsightFace.
        if self._production and set(normalized) != expected:
            raise ModelSupplyChainError("model manifest contains unexpected files")
        self._model_files = tuple(normalized)
        return normalized

    @staticmethod
    def _sha256_file(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _verify_model_dir(self, model_dir: str) -> bool:
        """Verify a complete local model pack against the manifest."""

        if self._model_manifest is None:
            return all(
                os.path.isfile(os.path.join(model_dir, filename))
                and os.path.getsize(os.path.join(model_dir, filename)) > 0
                for filename in self._model_files
            )
        try:
            for filename, metadata in self._model_manifest.items():
                path = os.path.join(model_dir, filename)
                if not os.path.isfile(path):
                    return False
                if os.path.getsize(path) != metadata["size"]:
                    return False
                if self._sha256_file(path) != metadata["sha256"]:
                    return False
        except (OSError, TypeError):
            return False
        return True

    def _install_from_bucket(self, gcs_bucket: object, local_model_dir: str) -> None:
        """Download and install a verified pack through a temp directory."""

        parent_dir = os.path.dirname(local_model_dir)
        os.makedirs(parent_dir, exist_ok=True)
        temp_dir = tempfile.mkdtemp(
            prefix=f".{self._model_name}.install-", dir=parent_dir
        )
        backup_dir = None
        try:
            for model_file in self._model_files:
                gcs_path = f"models/{self._model_name}/{model_file}"
                blob = gcs_bucket.blob(gcs_path)
                exists = getattr(blob, "exists", None)
                if callable(exists) and not exists():
                    raise ModelSupplyChainError(f"model artifact missing: {gcs_path}")
                temp_path = os.path.join(temp_dir, f"{model_file}.part")
                blob.download_to_filename(temp_path)
                if not os.path.isfile(temp_path):
                    raise ModelSupplyChainError(f"model artifact missing: {gcs_path}")
                metadata = self._model_manifest.get(model_file) if self._model_manifest else None
                if metadata is not None:
                    if os.path.getsize(temp_path) != metadata["size"]:
                        raise ModelSupplyChainError(f"model artifact size mismatch: {gcs_path}")
                    if self._sha256_file(temp_path) != metadata["sha256"]:
                        raise ModelSupplyChainError(f"model artifact digest mismatch: {gcs_path}")
                elif os.path.getsize(temp_path) <= 0:
                    raise ModelSupplyChainError(f"empty model artifact: {gcs_path}")
                os.replace(temp_path, os.path.join(temp_dir, model_file))

            if not self._verify_model_dir(temp_dir):
                raise ModelSupplyChainError("model artifact verification failed")

            if os.path.exists(local_model_dir):
                backup_dir = tempfile.mkdtemp(
                    prefix=f".{self._model_name}.old-", dir=parent_dir
                )
                os.rmdir(backup_dir)
                os.replace(local_model_dir, backup_dir)
            os.replace(temp_dir, local_model_dir)
            temp_dir = None
            if backup_dir:
                shutil.rmtree(backup_dir, ignore_errors=True)
                backup_dir = None
        except Exception:
            if backup_dir and not os.path.exists(local_model_dir):
                try:
                    os.replace(backup_dir, local_model_dir)
                    backup_dir = None
                except OSError:
                    pass
            raise
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            if backup_dir and os.path.exists(backup_dir):
                shutil.rmtree(backup_dir, ignore_errors=True)

    def _ensure_models(self, gcs_bucket: Optional[object] = None) -> None:
        """Ensure local ONNX model files exist, downloading from GCS if needed.

        Args:
            gcs_bucket: Google Cloud Storage Bucket (or None for local dev)
        """
        # InsightFace resolves ``root/models/<pack>``.  Keeping downloads in
        # ``root/<pack>`` causes a second download (or an offline cold-start
        # failure) when FaceAnalysis is initialised with the same root.
        local_model_dir = os.path.join(self._model_root, "models", self._model_name)

        if self._verify_model_dir(local_model_dir):
            logger.info("Using cached models at %s", local_model_dir)
            return

        if self._production and self._model_manifest is None:
            raise ModelSupplyChainError("production model manifest is required")

        if gcs_bucket is not None:
            self._install_from_bucket(gcs_bucket, local_model_dir)
            return

        if not self._allow_internet_fallback:
            raise ModelSupplyChainError(
                "verified model artifacts unavailable and Internet fallback is disabled"
            )

        # Local test/dev compatibility only.  Production never reaches this
        # branch, and therefore InsightFace cannot download an unpinned pack.
        logger.info(
            "No verified GCS model pack configured; local development may use "
            "InsightFace's existing fallback"
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
        if not image_bytes:
            return None
        try:
            nparr = np.frombuffer(image_bytes, np.uint8)
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if image is None or image.size == 0:
                return None
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

            # Do not rely on detector ordering.  Select the highest score and
            # use the bounding box as a stable tie-breaker for reproducibility.
            def face_sort_key(face):
                try:
                    score = float(getattr(face, "det_score", 0.0))
                except (TypeError, ValueError):
                    score = 0.0
                bbox = getattr(face, "bbox", [])
                try:
                    bbox_key = tuple(float(x) for x in bbox)[:4]
                except (TypeError, ValueError):
                    bbox_key = (float("inf"),) * 4
                return (-score, bbox_key)

            selected = sorted(faces, key=face_sort_key)[0]
            raw_embedding = selected.embedding
            embedding = validate_embedding(
                raw_embedding.tolist()
                if hasattr(raw_embedding, "tolist")
                else raw_embedding
            )
            # InsightFace embeddings are normalized for storage and matching.
            norm = float(np.linalg.norm(np.asarray(embedding, dtype=np.float64)))
            embedding = (np.asarray(embedding, dtype=np.float64) / norm).tolist()

            logger.debug("Extracted embedding, dim=%d, norm=%.4f", len(embedding), norm)
            return embedding
        except ValueError as e:
            logger.warning("Invalid face embedding: %s", e)
            return None
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
