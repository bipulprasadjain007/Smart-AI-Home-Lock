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
from werkzeug.wrappers import Response

from app import create_app
from app.face import FaceEngine

logging.basicConfig(level=logging.INFO)

# --- Firebase Admin SDK ---
# Supports both local dev (with .env GOOGLE_APPLICATION_CREDENTIALS path)
# and Cloud Functions deployment (uses Application Default Credentials).
_CRED_PATH = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
_STORAGE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET", "")
_PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
_MODEL_MANIFEST = (
    os.environ.get("MODEL_MANIFEST_JSON")
    or os.environ.get("MODEL_MANIFEST_PATH")
    or os.environ.get("MODEL_MANIFEST")
)

_fb_options = {}
if _PROJECT_ID:
    _fb_options["projectId"] = _PROJECT_ID

if not getattr(firebase_admin, "_apps", {}):
    if _CRED_PATH and os.path.isfile(_CRED_PATH):
        cred = credentials.Certificate(_CRED_PATH)
        firebase_admin.initialize_app(
            cred, options=_fb_options if _fb_options else None
        )
    else:
        firebase_admin.initialize_app(options=_fb_options if _fb_options else None)

db = firestore.client()
bucket = gcs.Client().bucket(_STORAGE_BUCKET) if _STORAGE_BUCKET else None

# --- InsightFace model ---
_det_size_raw = os.environ.get("DETECTION_SIZE", "640,640")
_det_size = tuple(int(x) for x in _det_size_raw.split(",")[:2])
face_engine = FaceEngine(
    model_name="buffalo_l",
    det_size=_det_size,
    gcs_bucket=bucket,
    model_manifest=_MODEL_MANIFEST,
    production=True,
    allow_internet_fallback=False,
)

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
    auth_bypass=False,
    device_credentials=os.environ.get("DEVICE_CREDENTIALS_JSON", "{}"),
)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        logging.warning("Ignoring invalid integer environment value for %s", name)
        return default


# Keep deployment policy in environment/configuration rather than source.  The
# app factory supplies safe production defaults; these settings allow deploy.sh
# to tighten request limits without changing route code.
app.config["V1_LEGACY_ENABLED"] = _env_bool("V1_LEGACY_ENABLED", False)
app.config["V1_LEGACY_ALLOW_UNLOCK"] = _env_bool(
    "V1_LEGACY_ALLOW_UNLOCK", False
)
app.config["V2_AUTH_ENABLED"] = _env_bool("V2_AUTH_ENABLED", True)
app.config["V2_ALLOW_MEDIUM_UNLOCK"] = _env_bool(
    "V2_ALLOW_MEDIUM_UNLOCK", False
)
app.config["V2_ADAPTIVE_LEARNING"] = _env_bool(
    "V2_ADAPTIVE_LEARNING", False
)
app.config["GENERATE_SIGNED_IMAGE_URLS"] = _env_bool(
    "GENERATE_SIGNED_IMAGE_URLS", False
)
app.config["ADMIN_TLS_PAYLOAD_ENABLED"] = _env_bool(
    "ADMIN_TLS_PAYLOAD_ENABLED", True
)
app.config["ADMIN_TLS_REQUIRE_HTTPS"] = _env_bool(
    "ADMIN_TLS_REQUIRE_HTTPS", True
)
app.config["MAX_CONTENT_LENGTH"] = _env_int(
    "MAX_REQUEST_BYTES", app.config["MAX_CONTENT_LENGTH"]
)
app.config["MAX_ENCRYPTED_IMAGE_BYTES"] = _env_int(
    "MAX_IMAGE_BYTES", app.config["MAX_ENCRYPTED_IMAGE_BYTES"]
)
app.config["MAX_ENCRYPTED_UNLOCK_BYTES"] = _env_int(
    "MAX_IMAGE_BYTES", app.config["MAX_ENCRYPTED_UNLOCK_BYTES"]
)
app.config["MAX_DECRYPTED_IMAGE_BYTES"] = _env_int(
    "MAX_IMAGE_BYTES", app.config["MAX_DECRYPTED_IMAGE_BYTES"]
)
app.config["MAX_IMAGE_PIXELS"] = _env_int(
    "MAX_IMAGE_PIXELS", app.config.get("MAX_IMAGE_PIXELS", 16 * 1024 * 1024)
)


@functions_framework.http
def main(request):
    """Functions Framework entrypoint for Google Cloud Functions deployment."""
    # ``Response.from_app`` is the supported WSGI bridge: unlike discarding
    # start_response, it preserves Flask's status code, headers, and JSON body
    # when Functions Framework invokes the target with a Werkzeug request.
    return Response.from_app(app, request.environ)


if __name__ == "__main__":
    logging.info("Starting Smart AI Home Lock server on :8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
