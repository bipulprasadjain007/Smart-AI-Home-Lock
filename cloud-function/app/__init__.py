"""Cloud Function server package — app factory with dependency injection.

Provides create_app() that accepts pre-initialized services
so tests can inject mocks. Production main.py wires real Firebase,
InsightFace, and GCS clients.
"""

from flask import Flask


def create_app(face_engine, db, bucket, aes_key, testing=False):
    """Create and configure the Flask application.

    Args:
        face_engine: app.face.FaceEngine instance (or mock)
        db: firebase_admin.firestore client (or mock)
        bucket: google.cloud.storage Bucket (or mock)
        aes_key: 32-byte AES-256 key for payload decryption
        testing: If True, enable Flask test mode

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    app.config["FACE_ENGINE"] = face_engine
    app.config["DB"] = db
    app.config["BUCKET"] = bucket
    app.config["AES_KEY"] = aes_key

    if testing:
        app.config["TESTING"] = True

    # Register routes
    from app.routes import register_routes
    register_routes(app)

    return app
