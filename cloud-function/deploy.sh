#!/usr/bin/env bash
# Deploy Smart AI Home Lock to Google Cloud Functions (Gen 2).
#
# Production deployments use Secret Manager by default.  This script never
# reads a secret value in production, and secret values are never placed in a
# gcloud argument or printed to the terminal.
#
# Usage:
#   bash cloud-function/deploy.sh                 # production deployment
#   DEPLOY_MODE=staging bash cloud-function/deploy.sh
#   DEPLOY_MODE=local bash cloud-function/deploy.sh # run the local function
#
# Secret IDs can be overridden without exposing their values:
#   AES_KEY_SECRET=... DEVICE_CREDENTIALS_SECRET=... bash cloud-function/deploy.sh

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"

PROJECT="${PROJECT:-smart-ai-home-lock}"
REGION="${REGION:-us-central1}"
FUNCTION_NAME="${FUNCTION_NAME:-smart-lock}"
MEMORY="4096MB"
TIMEOUT="540s"
RUNTIME="python312"
SOURCE="${SOURCE:-${SCRIPT_DIR}}"
BUCKET="${FIREBASE_STORAGE_BUCKET:-smart-ai-home-lock-storage}"
DEPLOY_MODE="${DEPLOY_MODE:-production}"
VERIFY_TOOL="${SCRIPT_DIR}/tools/verify_infrastructure.py"
LIFECYCLE_FILE="${LIFECYCLE_FILE:-${SCRIPT_DIR}/tools/bucket-lifecycle.json}"
MODEL_MANIFEST_FILE="${MODEL_MANIFEST_FILE:-${SCRIPT_DIR}/tools/model-manifest.json}"
# This is deliberately a relative path in the deployed source tree.  It is a
# non-secret contract for the face lane, not a credential or a fallback model.
MODEL_MANIFEST_PATH="${MODEL_MANIFEST_PATH:-tools/model-manifest.json}"
MODEL_MANIFEST_VERSION=""
MODEL_MANIFEST_SHA256=""
MODEL_MANIFEST_URI="${MODEL_MANIFEST_URI:-}"

# Secret IDs are metadata, not secret values.  Keep them configurable so the
# same script can be used across projects without putting credentials in code.
AES_KEY_SECRET="${AES_KEY_SECRET:-${AES_KEY_SECRET_NAME:-smart-ai-home-lock-aes-key}}"
DEVICE_CREDENTIALS_SECRET="${DEVICE_CREDENTIALS_SECRET:-${DEVICE_CREDENTIALS_SECRET_NAME:-smart-ai-home-lock-device-credentials}}"
SECRET_VERSION="${SECRET_VERSION:-latest}"

# These are deliberately non-secret policy settings.  They are supplied on
# every deployment so a missing application default cannot weaken the policy.
MAX_REQUEST_BYTES="${MAX_REQUEST_BYTES:-12582912}"
MAX_IMAGE_BYTES="${MAX_IMAGE_BYTES:-2097152}"
MAX_IMAGE_PIXELS="${MAX_IMAGE_PIXELS:-16777216}"
CONFIGURE_TTL="${CONFIGURE_TTL:-true}"
CONFIGURE_BUCKET="${CONFIGURE_BUCKET:-false}"
VERIFY_MODEL_OBJECTS="${VERIFY_MODEL_OBJECTS:-true}"
RUNTIME_ENV_VARS=""

PLAINTEXT_ENV_FILE=""

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  deploy.sh                         Deploy with Secret Manager bindings.
  DEPLOY_MODE=staging deploy.sh     Same secure Secret Manager deployment.
  DEPLOY_MODE=staging-env deploy.sh Explicit, temporary plaintext staging fallback.
  DEPLOY_MODE=local deploy.sh       Run the cloud function locally using .env.

Production/staging requires these Secret Manager secrets (IDs are configurable):
  AES_KEY_SECRET (default: smart-ai-home-lock-aes-key)
  DEVICE_CREDENTIALS_SECRET (default: smart-ai-home-lock-device-credentials)

Every cloud deployment also verifies Firestore TTL, private bucket controls,
the versioned model manifest, and Gen 2/v2-only configuration.  Set
CONFIGURE_BUCKET=true only when the reviewed lifecycle policy should be
applied; the default is verification-only because lifecycle rules can delete
old log objects.  Model binaries and their published manifest must already be
present in the private bucket.  Set VERIFY_MODEL_OBJECTS=false only for a
staged metadata-only check; production defaults to downloading and hashing
each model artifact in a temporary directory.

The staging-env mode additionally requires ALLOW_PLAINTEXT_SECRET_ENV=true and
the AES_KEY and DEVICE_CREDENTIALS_JSON environment variables.  It is not a
production path; it creates a mode-0600 temporary env-vars file and removes it
on exit.  Prefer Secret Manager instead.
EOF
}

require_command() {
  local command_name="$1"
  command -v "${command_name}" >/dev/null 2>&1 || die "required command not found: ${command_name}"
}

prepare_model_manifest() {
  require_command python3
  [[ -r "${MODEL_MANIFEST_FILE}" ]] || die "model manifest is not readable: ${MODEL_MANIFEST_FILE}"
  [[ -r "${LIFECYCLE_FILE}" ]] || die "bucket lifecycle policy is not readable: ${LIFECYCLE_FILE}"

  # Validation is local and non-secret.  It rejects missing sizes, malformed
  # SHA-256 values, duplicate names, and an unexpected model pack before any
  # gcloud command is attempted.
  python3 "${VERIFY_TOOL}" manifest --manifest "${MODEL_MANIFEST_FILE}" >/dev/null \
    || die "model manifest validation failed; deployment stopped"

  MODEL_MANIFEST_VERSION="$(python3 - "${MODEL_MANIFEST_FILE}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest_file:
    print(json.load(manifest_file)["manifest_version"])
PY
)"
  MODEL_MANIFEST_SHA256="$(python3 - "${MODEL_MANIFEST_FILE}" <<'PY'
import hashlib
import sys

with open(sys.argv[1], "rb") as manifest_file:
    print(hashlib.sha256(manifest_file.read()).hexdigest())
PY
)"
  if [[ -z "${MODEL_MANIFEST_URI}" ]]; then
    MODEL_MANIFEST_URI="gs://${BUCKET}/models/buffalo_l/manifests/${MODEL_MANIFEST_VERSION}.json"
  fi

  RUNTIME_ENV_VARS="GOOGLE_CLOUD_PROJECT=${PROJECT},FIREBASE_STORAGE_BUCKET=${BUCKET},V2_AUTH_ENABLED=true,V1_LEGACY_ENABLED=false,V1_LEGACY_ALLOW_UNLOCK=false,V2_ALLOW_MEDIUM_UNLOCK=false,V2_ADAPTIVE_LEARNING=false,MAX_REQUEST_BYTES=${MAX_REQUEST_BYTES},MAX_IMAGE_BYTES=${MAX_IMAGE_BYTES},MAX_IMAGE_PIXELS=${MAX_IMAGE_PIXELS},MODEL_MANIFEST_PATH=${MODEL_MANIFEST_PATH},MODEL_MANIFEST_URI=${MODEL_MANIFEST_URI},MODEL_MANIFEST_VERSION=${MODEL_MANIFEST_VERSION},MODEL_MANIFEST_SHA256=${MODEL_MANIFEST_SHA256}"
}

validate_aes_key() {
  local key_value="${AES_KEY:-}"
  if [[ ! "${key_value}" =~ ^[[:xdigit:]]{64}$ ]]; then
    die "AES_KEY must be exactly 64 hexadecimal characters (32 bytes); its value was not displayed"
  fi
}

validate_plaintext_staging_environment() {
  if [[ "${ALLOW_PLAINTEXT_SECRET_ENV:-}" != "true" ]]; then
    die "staging-env requires explicit ALLOW_PLAINTEXT_SECRET_ENV=true; use Secret Manager for normal deployments"
  fi
  [[ -n "${AES_KEY:-}" ]] || die "staging-env requires AES_KEY in the environment; its value was not displayed"
  [[ -n "${DEVICE_CREDENTIALS_JSON:-}" ]] || die "staging-env requires DEVICE_CREDENTIALS_JSON in the environment; its value was not displayed"
  validate_aes_key

  # Validate JSON without echoing it.  Python's parser error is intentionally
  # discarded because malformed JSON errors can include input context.
  require_command python3
  if ! python3 -c 'import json, os; json.loads(os.environ["DEVICE_CREDENTIALS_JSON"])' >/dev/null 2>&1; then
    die "DEVICE_CREDENTIALS_JSON is not valid JSON; its value was not displayed"
  fi
}

run_infrastructure_preflight() {
  local skip_secret_metadata="$1"
  local preflight_args=(
    preflight
    --project "${PROJECT}"
    --bucket "${BUCKET}"
    --manifest "${MODEL_MANIFEST_FILE}"
    --manifest-uri "${MODEL_MANIFEST_URI}"
    --retention-days 90
    --lifecycle-prefix logs/
    --lifecycle-file "${LIFECYCLE_FILE}"
  )

  if [[ "${skip_secret_metadata}" == "true" ]]; then
    # The explicit staging-env path is the only cloud path allowed to skip
    # Secret Manager metadata; it is never used for production or normal
    # staging deployments.
    preflight_args+=(--skip-secret-metadata)
  else
    preflight_args+=(
      --aes-secret "${AES_KEY_SECRET}"
      --device-secret "${DEVICE_CREDENTIALS_SECRET}"
      --secret-version "${SECRET_VERSION}"
    )
  fi
  if [[ "${CONFIGURE_TTL}" == "true" ]]; then
    preflight_args+=(--configure-ttl)
  fi
  if [[ "${CONFIGURE_BUCKET}" == "true" ]]; then
    preflight_args+=(--configure-bucket)
  fi
  if [[ "${VERIFY_MODEL_OBJECTS}" == "true" ]]; then
    preflight_args+=(--verify-model-objects)
  fi

  require_command gcloud
  python3 "${VERIFY_TOOL}" "${preflight_args[@]}"
}

write_plaintext_staging_env_file() {
  require_command python3
  PLAINTEXT_ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/smart-lock-env.XXXXXX")"
  chmod 600 "${PLAINTEXT_ENV_FILE}"

  # The values are read from the environment by Python and written only to a
  # temporary mode-0600 YAML/JSON env-vars file.  They are not command-line
  # arguments and are removed by cleanup_plaintext_staging_env_file().
  if ! python3 - "${PLAINTEXT_ENV_FILE}" "${PROJECT}" "${BUCKET}" "${MODEL_MANIFEST_PATH}" "${MODEL_MANIFEST_URI}" "${MODEL_MANIFEST_VERSION}" "${MODEL_MANIFEST_SHA256}" <<'PY'
import json
import os
import sys

path, project, bucket, manifest_path, manifest_uri, manifest_version, manifest_sha256 = sys.argv[1:]
values = {
    "GOOGLE_CLOUD_PROJECT": project,
    "FIREBASE_STORAGE_BUCKET": bucket,
    "V2_AUTH_ENABLED": "true",
    "V1_LEGACY_ENABLED": "false",
    "V1_LEGACY_ALLOW_UNLOCK": "false",
    "V2_ALLOW_MEDIUM_UNLOCK": "false",
    "V2_ADAPTIVE_LEARNING": "false",
    "MAX_REQUEST_BYTES": os.environ.get("MAX_REQUEST_BYTES", "12582912"),
    "MAX_IMAGE_BYTES": os.environ.get("MAX_IMAGE_BYTES", "2097152"),
    "MAX_IMAGE_PIXELS": os.environ.get("MAX_IMAGE_PIXELS", "16777216"),
    "MODEL_MANIFEST_PATH": manifest_path,
    "MODEL_MANIFEST_URI": manifest_uri,
    "MODEL_MANIFEST_VERSION": manifest_version,
    "MODEL_MANIFEST_SHA256": manifest_sha256,
    "AES_KEY": os.environ["AES_KEY"],
    "DEVICE_CREDENTIALS_JSON": os.environ["DEVICE_CREDENTIALS_JSON"],
}
with open(path, "w", encoding="utf-8") as env_file:
    json.dump(values, env_file)
    env_file.write("\n")
PY
  then
    die "could not create the temporary staging environment file"
  fi
}

cleanup_plaintext_staging_env_file() {
  if [[ -n "${PLAINTEXT_ENV_FILE}" && -f "${PLAINTEXT_ENV_FILE}" ]]; then
    rm -f -- "${PLAINTEXT_ENV_FILE}"
  fi
}

run_local() {
  require_command functions-framework
  [[ -r "${ENV_FILE}" ]] || die "local mode requires .env at ${ENV_FILE}"

  # Local mode is the only mode that reads .env.  It is intentionally not a
  # deployment fallback: no local secret is sent to Google Cloud.
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
  validate_aes_key

  export GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT:-${PROJECT}}"
  export FIREBASE_STORAGE_BUCKET="${FIREBASE_STORAGE_BUCKET:-${BUCKET}}"
  BUCKET="${FIREBASE_STORAGE_BUCKET}"
  prepare_model_manifest
  export V2_AUTH_ENABLED=true
  export V1_LEGACY_ENABLED=false
  export V1_LEGACY_ALLOW_UNLOCK=false
  export V2_ALLOW_MEDIUM_UNLOCK=false
  export V2_ADAPTIVE_LEARNING=false
  export MAX_REQUEST_BYTES MAX_IMAGE_BYTES MAX_IMAGE_PIXELS
  export MODEL_MANIFEST_PATH MODEL_MANIFEST_URI MODEL_MANIFEST_VERSION MODEL_MANIFEST_SHA256

  printf 'Starting local %s on port %s (secrets remain local)\n' "${FUNCTION_NAME}" "${PORT:-8080}"
  (
    cd "${SOURCE}"
    exec functions-framework --target=main --port="${PORT:-8080}"
  )
}

deploy() {
  local environment_flag
  local secret_flag=()
  local remove_plaintext_flag=()

  prepare_model_manifest

  case "${DEPLOY_MODE}" in
    production|staging)
      run_infrastructure_preflight "false"
      environment_flag="--set-env-vars=${RUNTIME_ENV_VARS}"
      secret_flag=("--set-secrets=AES_KEY=${AES_KEY_SECRET}:${SECRET_VERSION},DEVICE_CREDENTIALS_JSON=${DEVICE_CREDENTIALS_SECRET}:${SECRET_VERSION}")
      # Do not retain a plaintext binding left by an older deployment.  This
      # removes only the two dangerous environment keys; it never rotates or
      # deletes a Secret Manager version.
      remove_plaintext_flag=("--remove-env-vars=AES_KEY,DEVICE_CREDENTIALS_JSON")
      ;;
    staging-env)
      validate_plaintext_staging_environment
      run_infrastructure_preflight "true"
      write_plaintext_staging_env_file
      environment_flag="--env-vars-file=${PLAINTEXT_ENV_FILE}"
      printf 'WARNING: deploying with the explicit plaintext staging fallback; Secret Manager is recommended\n' >&2
      ;;
    *)
      usage
      die "unknown DEPLOY_MODE: ${DEPLOY_MODE}"
      ;;
  esac

  require_command gcloud
  printf 'Deploying %s to %s (%s, %s, %s)\n' "${FUNCTION_NAME}" "${PROJECT}" "${RUNTIME}" "${MEMORY}" "${TIMEOUT}"

  # The production path contains only public configuration in
  # --set-env-vars.  AES_KEY and DEVICE_CREDENTIALS_JSON are supplied through
  # Secret Manager bindings, never through shell interpolation.
  gcloud functions deploy "${FUNCTION_NAME}" \
    --gen2 \
    --project="${PROJECT}" \
    --region="${REGION}" \
    --runtime="${RUNTIME}" \
    --trigger-http \
    --allow-unauthenticated \
    --entry-point=main \
    --memory="${MEMORY}" \
    --timeout="${TIMEOUT}" \
    --source="${SOURCE}" \
    "${environment_flag}" \
    "${remove_plaintext_flag[@]}" \
    "${secret_flag[@]}"

  if [[ "${DEPLOY_MODE}" == "production" || "${DEPLOY_MODE}" == "staging" ]]; then
    python3 "${VERIFY_TOOL}" function \
      --project "${PROJECT}" \
      --region "${REGION}" \
      --function "${FUNCTION_NAME}" \
      --bucket "${BUCKET}" \
      --manifest "${MODEL_MANIFEST_FILE}" \
      --manifest-uri "${MODEL_MANIFEST_URI}" \
      --aes-secret "${AES_KEY_SECRET}" \
      --device-secret "${DEVICE_CREDENTIALS_SECRET}" \
      --secret-version "${SECRET_VERSION}"
  else
    printf 'Staging-env completed resource preflight; plaintext fallback was not treated as a production binding\n' >&2
  fi

  local function_url
  function_url="$(gcloud functions describe "${FUNCTION_NAME}" \
    --gen2 \
    --project="${PROJECT}" \
    --region="${REGION}" \
    --format='value(serviceConfig.uri)')"
  [[ -n "${function_url}" ]] || die "Gen 2 deployment returned no service URL"
  printf 'Deployment complete. URL: %s\n' "${function_url}"
}

trap cleanup_plaintext_staging_env_file EXIT

case "${DEPLOY_MODE}" in
  local)
    run_local
    ;;
  production|staging|staging-env)
    deploy
    ;;
  *)
    usage
    die "unknown DEPLOY_MODE: ${DEPLOY_MODE}"
    ;;
esac
