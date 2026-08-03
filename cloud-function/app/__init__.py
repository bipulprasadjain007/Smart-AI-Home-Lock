"""Cloud Function server package — app factory with dependency injection.

Provides create_app() that accepts pre-initialized services
so tests can inject mocks. Production main.py wires real Firebase,
InsightFace, and GCS clients.
"""

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from app.protocol import parse_device_credentials


def create_app(
    face_engine,
    db,
    bucket,
    aes_key,
    testing: bool = False,
    *,
    auth_bypass: bool | None = None,
    device_credentials=None,
):
    """Create and configure the Flask application.

    Args:
        face_engine: app.face.FaceEngine instance (or mock)
        db: firebase_admin.firestore client (or mock)
        bucket: google.cloud.storage Bucket (or mock)
        aes_key: 32-byte AES-256 key for payload decryption
        testing: If True, enable Flask test mode.  Local/test mode also
            selects the explicitly supported v1 compatibility defaults.
        auth_bypass: Explicit local/test bypass for Firebase/device auth.  If
            omitted, ``testing=True`` is treated as the explicit test mode
            switch used by the existing injected test applications.  It is
            never enabled for production (``testing=False``).
        device_credentials: Validated or JSON-encoded DEVICE_CREDENTIALS_JSON
            value.  Device keys are retained only in application memory.

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    app.config["FACE_ENGINE"] = face_engine
    app.config["DB"] = db
    app.config["BUCKET"] = bucket
    app.config["AES_KEY"] = aes_key
    app.config["TESTING"] = bool(testing)

    # Defaults intentionally differ between the injected local test app and
    # production.  Production has no unauthenticated route except health.
    if auth_bypass is None:
        auth_bypass = bool(testing)
    app.config["AUTH_BYPASS"] = bool(auth_bypass)
    app.config["V1_LEGACY_ENABLED"] = bool(testing)
    app.config["V1_LEGACY_ALLOW_UNLOCK"] = bool(testing)
    app.config["V2_AUTH_ENABLED"] = True
    app.config["V2_ALLOW_MEDIUM_UNLOCK"] = False
    app.config["V2_ADAPTIVE_LEARNING"] = False
    app.config["REQUIRE_EXISTING_USER_FOR_PIN"] = not bool(testing)
    app.config["STRICT_IMAGE_VALIDATION"] = not bool(testing)
    app.config["FACE_SINGLE_FACE_POLICY"] = "highest_confidence"
    app.config["CLOCK_SKEW_SECONDS"] = 60
    app.config["REPLAY_TTL_SECONDS"] = 120
    # Durable per-device/user PIN failure policy.  The route implementation
    # stores counters in Firestore transactions; these values are policy only
    # and can be overridden by an injected test/production configuration.
    app.config["PIN_MAX_FAILURES"] = 5
    app.config["PIN_MAX_ATTEMPTS"] = 5  # compatibility alias
    app.config["PIN_FAILURE_WINDOW_SECONDS"] = 300
    app.config["PIN_LOCKOUT_SECONDS"] = 300  # compatibility alias
    app.config["PIN_LIMIT_COLLECTION"] = "pin_attempt_limits"

    # Flask's global cap prevents multipart parsing from accepting an
    # unbounded body.  Individual routes apply tighter encrypted-payload caps.
    app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024
    app.config["MAX_ENCRYPTED_IMAGE_BYTES"] = 2 * 1024 * 1024
    app.config["MAX_ENCRYPTED_UNLOCK_BYTES"] = 2 * 1024 * 1024
    app.config["MAX_ENCRYPTED_PIN_BYTES"] = 16 * 1024
    app.config["MAX_DECRYPTED_IMAGE_BYTES"] = 2 * 1024 * 1024
    app.config["MAX_DECRYPTED_PIN_BYTES"] = 64
    app.config["LEGACY_NUMERIC_LOG_CURSOR"] = bool(testing)
    app.config["GENERATE_SIGNED_IMAGE_URLS"] = False

    try:
        app.config["DEVICE_CREDENTIALS"] = parse_device_credentials(
            device_credentials
            if device_credentials is not None
            else app.config.get("DEVICE_CREDENTIALS_JSON", {})
        )
    except ValueError:
        # Invalid secret configuration must fail closed.  Raising here also
        # prevents a typo in Secret Manager JSON from becoming an open device
        # endpoint during a cold start.
        raise

    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(_error):
        return jsonify({"error": "request too large"}), 413

    @app.errorhandler(HTTPException)
    def _http_error(error):
        return jsonify({"error": error.description or "request failed"}), error.code

    @app.errorhandler(Exception)
    def _unhandled_error(_error):
        # Route handlers log the exception with context; never send exception
        # text, credentials, or backend details to a client.
        return jsonify({"error": "internal server error"}), 500

    # Register routes
    from app.routes import register_routes
    register_routes(app)

    return app
