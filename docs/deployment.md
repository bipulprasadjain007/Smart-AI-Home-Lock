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
MAX_REQUEST_BYTES=12582912
MAX_IMAGE_BYTES=2097152
MAX_IMAGE_PIXELS=16777216
```

The Cloud Function runtime identity must have Secret Manager Secret Accessor
permission on both secrets. Do not add either secret to `--set-env-vars`, a
source archive, or a committed `.env` file.

## Explicit local fallback

For local work only, activate the Python environment and run:

```bash
source SAHL/bin/activate
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
`pin.py` or `test-images/images-encryption.py`; both load `AES_KEY` from the
environment/ignored `.env` and use the cloud AES-256-GCM packet format:

```text
nonce (12 bytes) || tag (16 bytes) || ciphertext
```

Both helpers require their input explicitly and have no embedded key or PIN.
