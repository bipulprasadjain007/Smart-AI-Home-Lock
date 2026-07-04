"""API route handlers for the Smart AI Home Lock cloud function.

Endpoints:
  POST /api/register  — Register user with 5 encrypted face images
  POST /api/unlock    — Face unlock with 3-tier confidence matching
  GET  /api/health    — Health check
"""

import re
import time
import traceback
import logging

import numpy as np
from flask import current_app, jsonify, request

from app.encryption import aes_gcm_decrypt
from app.similarity import cosine_similarity

logger = logging.getLogger(__name__)

USER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,100}$")
THRESHOLD_HIGH = 0.75
THRESHOLD_MEDIUM_HIGH = 0.70
THRESHOLD_MEDIUM = 0.60


def register_routes(app):
    app.add_url_rule("/api/register", "register", register, methods=["POST"])
    app.add_url_rule("/api/unlock", "unlock", unlock, methods=["POST"])
    app.add_url_rule("/api/health", "health", health, methods=["GET"])


def health():
    return jsonify({"status": "ok"}), 200


def register():
    try:
        user_id = request.form.get("user_id", "").strip()
        if not USER_ID_PATTERN.match(user_id):
            return jsonify({"error": "Invalid user_id format"}), 400

        face_engine = current_app.config["FACE_ENGINE"]
        key = current_app.config["AES_KEY"]
        db = current_app.config["DB"]

        embeddings = {}
        for i in range(1, 6):
            field = f"image{i}"
            if field not in request.files:
                return jsonify({"error": f"Missing image {field}"}), 400

            file = request.files[field]
            encrypted_data = file.read()

            try:
                decrypted = aes_gcm_decrypt(encrypted_data, key)
            except (ValueError, TypeError, IndexError) as e:
                logger.warning("Decrypt failed for %s: %s", field, e)
                return jsonify({"error": f"Encryption error in {field}"}), 400

            embedding = face_engine.get_embedding(decrypted)
            if embedding is None:
                return jsonify({"error": f"No face detected in {field}"}), 400

            embeddings[field] = embedding

        from firebase_admin import firestore

        doc = {"timestamp": firestore.SERVER_TIMESTAMP}
        doc.update(embeddings)
        db.collection("users").document(user_id).set(doc)

        logger.info("Registered user=%s", user_id)
        return jsonify({"status": "Face registered", "user_id": user_id}), 200

    except Exception as e:
        logger.error("register error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": str(e)}), 500


def unlock():
    try:
        encrypted_data = request.data
        if not encrypted_data or len(encrypted_data) < 28:
            return jsonify({"error": "Empty or invalid payload"}), 400

        key = current_app.config["AES_KEY"]
        face_engine = current_app.config["FACE_ENGINE"]
        db = current_app.config["DB"]
        bucket = current_app.config["BUCKET"]

        try:
            decrypted = aes_gcm_decrypt(encrypted_data, key)
        except (ValueError, TypeError, IndexError) as e:
            logger.warning("Unlock decrypt failed: %s", e)
            return jsonify({"error": "Encryption error"}), 400

        embedding = face_engine.get_embedding(decrypted)
        if embedding is None:
            logger.debug("No face detected in unlock image")
            return jsonify({"status": "NO_FACE"}), 400

        embedding_np = np.array(embedding, dtype=np.float64)
        users = db.collection("users").stream()

        best_user_id = None
        best_similarity = 0.0

        for user_snap in users:
            user_data = user_snap.to_dict()
            for img_key in ("image1", "image2", "image3", "image4", "image5"):
                stored_emb = user_data.get(img_key)
                if stored_emb is None:
                    continue
                sim = cosine_similarity(embedding_np, stored_emb)
                if sim > best_similarity:
                    best_similarity = sim
                    best_user_id = user_snap.id

        if best_user_id is None:
            return jsonify({
                "status": "NO_MATCH",
                "similarity": 0.0,
                "weighted_similarity": 0.0,
            }), 200

        confidence = _confidence_label(best_similarity)

        if best_similarity >= THRESHOLD_MEDIUM:
            _log_event(db, bucket, best_user_id, decrypted, best_similarity, confidence)
            logger.info(
                "UNLOCK user=%s similarity=%.4f confidence=%s",
                best_user_id, best_similarity, confidence,
            )
            return jsonify({
                "status": "UNLOCK",
                "similarity": round(best_similarity, 6),
                "weighted_similarity": round(best_similarity, 6),
                "confidence": confidence,
            }), 200
        else:
            return jsonify({
                "status": "NO_MATCH",
                "similarity": round(best_similarity, 6),
                "weighted_similarity": round(best_similarity, 6),
            }), 200

    except Exception as e:
        logger.error("unlock error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": str(e)}), 500


def _confidence_label(similarity):
    if similarity >= THRESHOLD_HIGH:
        return "HIGH"
    elif similarity >= THRESHOLD_MEDIUM_HIGH:
        return "MEDIUM-HIGH"
    else:
        return "MEDIUM"


def _log_event(db, bucket, user_id, image_bytes, similarity, confidence):
    from firebase_admin import firestore

    ts = int(time.time())
    blob = bucket.blob(f"logs/{user_id}/{ts}.jpg")
    blob.upload_from_string(image_bytes, content_type="image/jpeg")
    image_url = blob.public_url

    db.collection("logs").add({
        "user_id": user_id,
        "timestamp": firestore.SERVER_TIMESTAMP,
        "image_url": image_url,
        "similarity": similarity,
        "confidence": confidence,
    })
