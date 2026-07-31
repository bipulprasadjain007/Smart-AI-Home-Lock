#!/usr/bin/env bash
# Deploy Smart AI Home Lock to Google Cloud Functions (Gen1)
# Usage: bash deploy.sh

set -euo pipefail

# Load AES_KEY from .env (gitignored, not committed)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"
if [ -f "${ENV_FILE}" ]; then
  set -a && source "${ENV_FILE}" && set +a
else
  echo "ERROR: .env not found at ${ENV_FILE}" >&2
  echo "Create .env with: AES_KEY=<64-hex-chars>" >&2
  exit 1
fi

if [ -z "${AES_KEY:-}" ] || [ ${#AES_KEY} -ne 64 ]; then
  echo "ERROR: AES_KEY must be 64 hex characters (32 bytes) in .env" >&2
  exit 1
fi

PROJECT="smart-ai-home-lock"
REGION="us-central1"
FUNCTION_NAME="smart-lock"
MEMORY="4096MB"
TIMEOUT="540s"
RUNTIME="python312"
SOURCE="${SCRIPT_DIR}"

echo "=== Deploying ${FUNCTION_NAME} to ${PROJECT} ==="
echo "Memory: ${MEMORY} | Timeout: ${TIMEOUT} | Source: ${SOURCE}"

gcloud functions deploy "${FUNCTION_NAME}" \
  --project="${PROJECT}" \
  --region="${REGION}" \
  --runtime="${RUNTIME}" \
  --trigger-http \
  --allow-unauthenticated \
  --entry-point=main \
  --memory="${MEMORY}" \
  --timeout="${TIMEOUT}" \
  --source="${SOURCE}" \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT},FIREBASE_STORAGE_BUCKET=smart-ai-home-lock-storage,AES_KEY=${AES_KEY}"

echo ""
echo "=== Deployment complete ==="
echo "URL: $(gcloud functions describe ${FUNCTION_NAME} --project=${PROJECT} --region=${REGION} --format='value(httpsTrigger.url)')"
