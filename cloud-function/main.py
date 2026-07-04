"""Production entrypoint for the Smart AI Home Lock Cloud Function.

Loads environment, initialises Firebase, InsightFace, and GCS,
then creates the Flask application wrapped by functions_framework.

To run locally:
    functions-framework --target main --port 8080
    or: python main.py
"""

import logging
import os

from dotenv import load_dotenv

load_dotenv()

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud import storage as gcs
import functions_framework

from app import create_app
from app.face import FaceEngine

logging.basicConfig(level=logging.INFO)

# --- Firebase Admin SDK ---
_CRED_PATH = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
_STORAGE_BUCKET = os.environ["FIREBASE_STORAGE_BUCKET"]

cred = credentials.Certificate(_CRED_PATH)
firebase_admin.initialize_app(cred)
db = firestore.client()
bucket = gcs.Client().bucket(_STORAGE_BUCKET)

# --- InsightFace model ---
face_engine = FaceEngine(model_name="buffalo_l", det_size=(640, 640))

# --- AES-256 key ---
aes_key = bytes.fromhex(os.environ["AES_KEY"])
if len(aes_key) != 32:
    raise ValueError(
        f"AES_KEY must be 32 bytes (64 hex chars), got {len(aes_key)} bytes. "
        "For AES-256-GCM, generate a 32-byte key: python -c 'import os; print(os.urandom(32).hex())'"
    )

# --- Flask application ---
app = create_app(
    face_engine=face_engine,
    db=db,
    bucket=bucket,
    aes_key=aes_key,
    testing=False,
)


@functions_framework.http
def main(request):
    """Functions Framework entrypoint for Google Cloud Functions deployment."""
    return app(request.environ, lambda status, headers: None)


if __name__ == "__main__":
    logging.info("Starting Smart AI Home Lock server on :8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
