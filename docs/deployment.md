# Deployment and legacy migration

## Production deployment

`cloud-function/deploy.sh` is the only deployment path. It targets the
`cloud-function/main.py` Functions Framework entrypoint with Python 3.12,
4096 MB memory, and a 540 second timeout.

Production and staging deployments require two Secret Manager secrets:

- `AES_KEY`: a 64-hex-character AES-256 key;
- `DEVICE_CREDENTIALS_JSON`: the validated device-credential document.

The script checks only secret metadata and an accessible version. It never
reads or prints a secret payload. Secret IDs may be supplied as
`AES_KEY_SECRET` and `DEVICE_CREDENTIALS_SECRET`; they default to
`smart-ai-home-lock-aes-key` and `smart-ai-home-lock-device-credentials`.

The deployment sets these non-secret policy defaults:

```text
V2_AUTH_ENABLED=true
V1_LEGACY_ENABLED=false
V1_LEGACY_ALLOW_UNLOCK=false
V2_ALLOW_MEDIUM_UNLOCK=false
V2_ADAPTIVE_LEARNING=false
ADMIN_TLS_PAYLOAD_ENABLED=true
ADMIN_TLS_REQUIRE_HTTPS=true
MAX_REQUEST_BYTES=12582912
MAX_IMAGE_BYTES=2097152
MAX_IMAGE_PIXELS=16777216
```

The deployed service also exposes `GET /api/device_time`. It is not a public
clock: the request must carry a device-generated nonce and HMAC, and the
response timestamp is bound to that nonce with the same provisioned device
credential. Firmware must complete this exchange before sending an unlock.

The Cloud Function runtime identity must have Secret Manager Secret Accessor
permission on both secrets. Do not add either secret to `--set-env-vars`, a
source archive, or a committed `.env` file.

The Flutter administrator app uses Firebase bearer authentication and HTTPS
for enrollment photos and PIN setup. It sends
`X-Admin-Payload-Protection: tls`; the production service rejects this mode on
insecure transport. This avoids placing the server/device AES key in a mobile
application. ESP32 unlock and PIN-unlock requests still require AES-GCM plus
the complete protocol-v2 HMAC envelope.

## Verified model manifest

The three `buffalo_l` ONNX binaries are deployment inputs and are not stored in
the repository. Generate the ignored runtime manifest from the exact artifacts
that will be uploaded to the private bucket:

```bash
python3 cloud-function/tools/build_model_manifest.py \
  --model-dir /path/to/reviewed/buffalo_l \
  --version buffalo_l-v1 \
  --output cloud-function/tools/model-manifest.json
python3 cloud-function/tools/verify_infrastructure.py manifest \
  --manifest cloud-function/tools/model-manifest.json
```

Upload those exact binaries beneath the manifest's `artifact_prefix` and
publish the same manifest at the `MODEL_MANIFEST_URI`. The deployment preflight
downloads and hashes each object by default. It rejects missing, pending, or
handwritten placeholder manifests before invoking a deployment.

## Explicit local fallback

For local work only, activate the Python environment and run:

```bash
source .venv/bin/activate
DEPLOY_MODE=local bash cloud-function/deploy.sh
```

Local mode reads the ignored root `.env`, starts the canonical cloud function,
and does not call Google Cloud or upload local secret values. Staging should
use Secret Manager. If a short-lived staging exception is unavoidable,
`DEPLOY_MODE=staging-env` requires
`ALLOW_PLAINTEXT_SECRET_ENV=true`, `AES_KEY`, and
`DEVICE_CREDENTIALS_JSON`; it uses a temporary mode-0600 env file and removes
it on exit. This mode is not suitable for production.

## Legacy files

The repository-root `main.py` is a migration guard and intentionally cannot
serve requests. Deploying it would fail with migration guidance rather than
starting the former insecure API. Generate client packets with the root
`pin.py` loads `AES_KEY` from the environment/ignored `.env` and uses the cloud
AES-256-GCM packet format:

```text
nonce (12 bytes) || tag (16 bytes) || ciphertext
```

Both helpers require their input explicitly and have no embedded key or PIN.
