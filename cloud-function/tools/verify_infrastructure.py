#!/usr/bin/env python3
"""Fail-closed deployment checks for non-secret Google Cloud infrastructure.

The checker intentionally captures gcloud output and only emits short policy
errors.  It never calls ``secrets versions access`` and never prints resource
JSON, secret values, model bytes, or credential material.

Examples:
  verify_infrastructure.py preflight --project PROJECT --bucket BUCKET ...
  verify_infrastructure.py function --project PROJECT --region REGION ...
  verify_infrastructure.py manifest --manifest cloud-function/tools/model-manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


EXPECTED_MODEL_FILES = {"det_10g.onnx", "w600k_r50.onnx", "2d106det.onnx"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SECRET_KEYS = {"AES_KEY", "DEVICE_CREDENTIALS_JSON"}
V2_ENV_DEFAULTS = {
    "V2_AUTH_ENABLED": "true",
    "V1_LEGACY_ENABLED": "false",
    "V1_LEGACY_ALLOW_UNLOCK": "false",
    "V2_ALLOW_MEDIUM_UNLOCK": "false",
    "V2_ADAPTIVE_LEARNING": "false",
    "ADMIN_TLS_PAYLOAD_ENABLED": "true",
    "ADMIN_TLS_REQUIRE_HTTPS": "true",
}


class CheckError(RuntimeError):
    """A safe, user-facing infrastructure check failure."""


def _fail(message: str) -> CheckError:
    return CheckError(message)


def _run_gcloud(args: list[str], *, input_bytes: bytes | None = None) -> str:
    """Run gcloud without exposing its output on success or failure."""

    try:
        completed = subprocess.run(
            ["gcloud", *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise _fail("gcloud could not be executed") from exc
    if completed.returncode != 0:
        raise _fail(f"gcloud check failed (exit {completed.returncode})")
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail("gcloud returned non-text metadata") from exc


def _run_gcloud_bytes(args: list[str]) -> bytes:
    """Capture a non-secret object (the JSON manifest) without printing it."""

    try:
        completed = subprocess.run(
            ["gcloud", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise _fail("gcloud could not be executed") from exc
    if completed.returncode != 0:
        raise _fail(f"gcloud object check failed (exit {completed.returncode})")
    return completed.stdout


def _json(text: str, description: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise _fail(f"{description} did not return valid JSON metadata") from exc


def _normalise_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalise_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _bucket_uri(bucket: str) -> str:
    value = bucket.strip()
    if value.startswith("gs://"):
        value = value[5:]
    if not value or "/" in value or "\\" in value:
        raise _fail("bucket must be a bucket name, not an object path")
    return f"gs://{value}"


def _nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _manifest_from_file(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise _fail(f"model manifest is not readable: {path}") from exc
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("model manifest is not valid UTF-8 JSON") from exc
    _validate_manifest(manifest)
    return manifest, hashlib.sha256(raw).hexdigest()


def _validate_manifest(manifest: Any) -> None:
    if not isinstance(manifest, dict):
        raise _fail("model manifest must be a JSON object")
    if manifest.get("schema_version") != 1:
        raise _fail("model manifest schema_version must be 1")
    version = manifest.get("manifest_version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise _fail("model manifest has an invalid manifest_version")
    if manifest.get("model_name") != "buffalo_l":
        raise _fail("model manifest model_name must be buffalo_l")
    prefix = manifest.get("artifact_prefix")
    if (
        not isinstance(prefix, str)
        or not prefix
        or prefix.startswith("/")
        or "\\" in prefix
        or any(part in {"", ".", ".."} for part in prefix.split("/"))
    ):
        raise _fail("model manifest artifact_prefix must be a relative path")
    if manifest.get("verification_status") != "verified-at-build-time":
        raise _fail("model manifest must be verified-at-build-time")

    files = manifest.get("files")
    if not isinstance(files, list) or {item.get("name") for item in files if isinstance(item, dict)} != EXPECTED_MODEL_FILES:
        raise _fail("model manifest must contain exactly the three buffalo_l ONNX files")
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise _fail("model manifest file entries must be objects")
        name = item.get("name")
        if name in seen or name not in EXPECTED_MODEL_FILES:
            raise _fail("model manifest contains a duplicate or unexpected file")
        seen.add(name)
        if Path(name).name != name or "/" in name or "\\" in name:
            raise _fail("model manifest file names must be plain file names")
        size = item.get("expected_size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise _fail(f"model manifest has an invalid expected size for {name}")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise _fail(f"model manifest has an invalid SHA-256 for {name}")


def _check_auth_and_project(project: str) -> None:
    accounts = _run_gcloud(
        ["auth", "list", "--filter=status:ACTIVE", "--format=value(account)"]
    ).strip()
    if not accounts:
        raise _fail("gcloud has no active authenticated account")
    project_id = _run_gcloud(
        ["projects", "describe", project, "--format=value(projectId)"]
    ).strip()
    if project_id != project:
        raise _fail("gcloud cannot verify the requested project")


def _check_secret_metadata(project: str, secret: str, version: str, label: str) -> None:
    if not secret or "/" in secret or "\\" in secret:
        raise _fail(f"{label} Secret Manager ID is invalid")
    name = _run_gcloud(
        ["secrets", "describe", secret, "--project", project, "--format=value(name)"]
    ).strip()
    if not name:
        raise _fail(f"{label} Secret Manager secret metadata is empty")
    version_name = _run_gcloud(
        [
            "secrets",
            "versions",
            "describe",
            version,
            "--secret",
            secret,
            "--project",
            project,
            "--format=value(name)",
        ]
    ).strip()
    if not version_name:
        raise _fail(f"{label} Secret Manager version metadata is empty")


def _ttl_state(metadata: Any) -> str:
    for candidate in (
        _nested(metadata, "ttlConfig", "state"),
        _nested(metadata, "ttl_config", "state"),
        _nested(metadata, "field", "ttlConfig", "state"),
        _nested(metadata, "state"),
    ):
        if candidate is not None:
            return _normalise_text(candidate).upper()
    if isinstance(metadata, str):
        return metadata.strip().upper()
    return ""


def _check_ttl(project: str, configure: bool) -> None:
    ttl_args = [
        "firestore",
        "fields",
        "ttls",
        "update",
        "expires_at",
        "--collection-group=device_request_replays",
        "--enable-ttl",
        "--project",
        project,
    ]
    if configure:
        # This is an idempotent enable operation.  It never deletes a field,
        # collection, document, or credential.
        _run_gcloud(ttl_args)
    metadata = _json(
        _run_gcloud(
            [
                "firestore",
                "fields",
                "ttls",
                "describe",
                "expires_at",
                "--collection-group=device_request_replays",
                "--project",
                project,
                "--format=json",
            ]
        ),
        "Firestore TTL metadata",
    )
    if _ttl_state(metadata) != "ACTIVE":
        raise _fail(
            "Firestore TTL is not ACTIVE for device_request_replays.expires_at; deployment stopped"
        )


def _has_public_member(policy: Any) -> bool:
    if not isinstance(policy, dict):
        return True
    for binding in policy.get("bindings", []):
        if not isinstance(binding, dict):
            continue
        if any(
            member in {"allUsers", "allAuthenticatedUsers"}
            for member in binding.get("members", [])
        ):
            return True
    return False


def _lifecycle_matches(description: dict[str, Any], retention_days: int, prefix: str) -> bool:
    lifecycle = description.get("lifecycle", {})
    rules = lifecycle.get("rule", []) if isinstance(lifecycle, dict) else []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        action = rule.get("action", {})
        condition = rule.get("condition", {})
        prefixes = condition.get("matchesPrefix", []) if isinstance(condition, dict) else []
        if (
            isinstance(action, dict)
            and action.get("type") == "Delete"
            and isinstance(condition, dict)
            and condition.get("age") == retention_days
            and prefix in prefixes
        ):
            return True
    return False


def _check_bucket(
    project: str,
    bucket: str,
    retention_days: int,
    lifecycle_prefix: str,
    configure: bool,
    lifecycle_file: Path,
) -> None:
    uri = _bucket_uri(bucket)
    if configure:
        _run_gcloud(
            [
                "storage",
                "buckets",
                "update",
                uri,
                "--project",
                project,
                "--uniform-bucket-level-access",
                "--public-access-prevention=enforced",
            ]
        )
        _run_gcloud(
            [
                "storage",
                "buckets",
                "update",
                uri,
                "--project",
                project,
                f"--lifecycle-file={lifecycle_file}",
            ]
        )

    description = _json(
        _run_gcloud(
            [
                "storage",
                "buckets",
                "describe",
                uri,
                "--project",
                project,
                "--format=json",
            ]
        ),
        "Cloud Storage bucket metadata",
    )
    iam = description.get("iamConfiguration", {})
    if not isinstance(iam, dict) or not _normalise_bool(
        _nested(iam, "uniformBucketLevelAccess", "enabled")
    ):
        raise _fail("bucket must have Uniform Bucket-Level Access enabled")
    if _normalise_text(iam.get("publicAccessPrevention")).lower() != "enforced":
        raise _fail("bucket must have Public Access Prevention enforced")
    if not _lifecycle_matches(description, retention_days, lifecycle_prefix):
        raise _fail(
            f"bucket lacks the required Delete lifecycle rule for {lifecycle_prefix!r} at {retention_days} days"
        )

    policy = _json(
        _run_gcloud(["storage", "buckets", "get-iam-policy", uri, "--format=json"]),
        "Cloud Storage IAM metadata",
    )
    if _has_public_member(policy):
        raise _fail("bucket IAM policy contains a public member; biometric objects must remain private")


def _manifest_object_uri(manifest: dict[str, Any], manifest_uri: str) -> str:
    if not manifest_uri.startswith("gs://") or len(manifest_uri) <= len("gs://"):
        raise _fail("MODEL_MANIFEST_URI must be a non-empty gs:// URI")
    return manifest_uri


def _compare_manifest_values(expected: dict[str, Any], actual: dict[str, Any]) -> None:
    if expected != actual:
        raise _fail("published model manifest does not match the deployment manifest")


def _check_manifest_remote(
    project: str,
    bucket: str,
    manifest: dict[str, Any],
    manifest_uri: str,
    verify_model_objects: bool,
) -> None:
    uri = _manifest_object_uri(manifest, manifest_uri)
    expected_bucket = _bucket_uri(bucket)
    actual_bucket = f"gs://{uri[5:].split('/', 1)[0]}"
    if actual_bucket != expected_bucket:
        raise _fail("model manifest must be published in the configured private bucket")
    metadata = _json(
        _run_gcloud(
            [
                "storage",
                "objects",
                "describe",
                uri,
                "--project",
                project,
                "--format=json",
            ]
        ),
        "published model manifest metadata",
    )
    if not metadata:
        raise _fail("published model manifest metadata is empty")
    remote_bytes = _run_gcloud_bytes(["storage", "cat", uri, "--project", project])
    try:
        remote_manifest = json.loads(remote_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("published model manifest is not valid UTF-8 JSON") from exc
    _validate_manifest(remote_manifest)
    _compare_manifest_values(manifest, remote_manifest)

    if not verify_model_objects:
        return
    prefix = manifest["artifact_prefix"].rstrip("/")
    with tempfile.TemporaryDirectory(prefix="sahl-model-check-") as temp_dir:
        for item in manifest["files"]:
            name = item["name"]
            destination = Path(temp_dir) / name
            artifact_uri = f"gs://{uri[5:].split('/', 1)[0]}/{prefix}/{name}"
            try:
                completed = subprocess.run(
                    [
                        "gcloud",
                        "storage",
                        "cp",
                        artifact_uri,
                        str(destination),
                        "--project",
                        project,
                        "--quiet",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            except OSError as exc:
                raise _fail("gcloud could not be executed for model verification") from exc
            if completed.returncode != 0:
                raise _fail(f"model artifact could not be downloaded for {name}")
            if not destination.is_file():
                raise _fail(f"model artifact download did not produce {name}")
            if destination.stat().st_size != item["expected_size_bytes"]:
                raise _fail(f"model artifact size mismatch for {name}")
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            if digest != item["sha256"]:
                raise _fail(f"model artifact SHA-256 mismatch for {name}")


def _secret_name(value: Any) -> str:
    text = _normalise_text(value)
    return text.rsplit("/", 1)[-1]


def _secret_bindings(service_config: dict[str, Any]) -> dict[str, dict[str, str]]:
    bindings: dict[str, dict[str, str]] = {}
    values = service_config.get("secretEnvironmentVariables", [])
    if not isinstance(values, list):
        return bindings
    for value in values:
        if not isinstance(value, dict):
            continue
        key = _normalise_text(value.get("key"))
        if key:
            bindings[key] = {
                "secret": _secret_name(value.get("secret")),
                "version": _normalise_text(value.get("version")),
            }
    return bindings


def _environment_values(service_config: dict[str, Any]) -> dict[str, str]:
    values = service_config.get("environmentVariables", {})
    if not isinstance(values, dict):
        return {}
    return {str(key): _normalise_text(value) for key, value in values.items()}


def _check_function(
    project: str,
    region: str,
    function: str,
    aes_secret: str,
    device_secret: str,
    secret_version: str,
    expected_env: dict[str, str],
    manifest_sha256: str,
) -> None:
    metadata = _json(
        _run_gcloud(
            [
                "functions",
                "describe",
                function,
                "--gen2",
                "--project",
                project,
                "--region",
                region,
                "--format=json",
            ]
        ),
        "Cloud Function metadata",
    )
    environment = _normalise_text(metadata.get("environment")).replace("_", "").upper()
    if environment != "GEN2":
        raise _fail("deployed function is not Gen 2")
    service_config = metadata.get("serviceConfig")
    if not isinstance(service_config, dict):
        raise _fail("deployed Gen 2 function has no service configuration")
    env = _environment_values(service_config)
    for key, value in expected_env.items():
        if env.get(key) != value:
            raise _fail(f"deployed function policy environment is not locked: {key}")
    if env.get("MODEL_MANIFEST_SHA256") != manifest_sha256:
        raise _fail("deployed function model manifest digest does not match the reviewed file")
    leaked = SECRET_KEYS.intersection(env)
    if leaked:
        raise _fail("deployed function contains a plaintext secret environment binding")

    bindings = _secret_bindings(service_config)
    expected = {
        "AES_KEY": (aes_secret, secret_version),
        "DEVICE_CREDENTIALS_JSON": (device_secret, secret_version),
    }
    for key, (secret, version) in expected.items():
        binding = bindings.get(key)
        if not binding or binding["secret"] != secret or binding["version"] != version:
            raise _fail(f"deployed function is missing the required Secret Manager binding for {key}")


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", required=True)
    parser.add_argument("--bucket", required=False)
    parser.add_argument("--manifest", required=False, type=Path)
    parser.add_argument("--manifest-uri", required=False)
    parser.add_argument("--function", required=False)
    parser.add_argument("--region", required=False)
    parser.add_argument("--aes-secret", required=False)
    parser.add_argument("--device-secret", required=False)
    parser.add_argument("--secret-version", default="latest")
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--lifecycle-prefix", default="logs/")
    parser.add_argument("--lifecycle-file", type=Path)


def _load_required_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    if args.manifest is None:
        raise _fail("--manifest is required")
    return _manifest_from_file(args.manifest)


def _require(value: Any, name: str) -> str:
    text = _normalise_text(value)
    if not text:
        raise _fail(f"--{name} is required")
    return text


def _preflight(args: argparse.Namespace) -> None:
    project = _require(args.project, "project")
    bucket = _require(args.bucket, "bucket")
    manifest, manifest_sha = _load_required_manifest(args)
    manifest_uri = _require(args.manifest_uri, "manifest-uri")
    if args.retention_days <= 0:
        raise _fail("--retention-days must be positive")
    if not args.lifecycle_prefix:
        raise _fail("--lifecycle-prefix must not be empty")
    lifecycle_file = args.lifecycle_file
    if lifecycle_file is None:
        lifecycle_file = Path(__file__).with_name("bucket-lifecycle.json")

    _check_auth_and_project(project)
    if not args.skip_secret_metadata:
        aes_secret = _require(args.aes_secret, "aes-secret")
        device_secret = _require(args.device_secret, "device-secret")
        _check_secret_metadata(project, aes_secret, args.secret_version, "AES_KEY")
        _check_secret_metadata(
            project, device_secret, args.secret_version, "DEVICE_CREDENTIALS_JSON"
        )
    _check_ttl(project, args.configure_ttl)
    _check_bucket(
        project,
        bucket,
        args.retention_days,
        args.lifecycle_prefix,
        args.configure_bucket,
        lifecycle_file,
    )
    _check_manifest_remote(
        project, bucket, manifest, manifest_uri, args.verify_model_objects
    )
    print(
        "Infrastructure preflight passed: Secret Manager metadata, Gen 2 policy, "
        "Firestore TTL, private bucket retention, and model manifest"
    )


def _function_check(args: argparse.Namespace) -> None:
    project = _require(args.project, "project")
    region = _require(args.region, "region")
    function = _require(args.function, "function")
    aes_secret = _require(args.aes_secret, "aes-secret")
    device_secret = _require(args.device_secret, "device-secret")
    manifest, manifest_sha = _load_required_manifest(args)
    # Construct the expected non-secret environment from the reviewed file.
    expected_env = dict(V2_ENV_DEFAULTS)
    expected_env.update(
        {
            "GOOGLE_CLOUD_PROJECT": project,
            "FIREBASE_STORAGE_BUCKET": _require(args.bucket, "bucket"),
            "MODEL_MANIFEST_VERSION": manifest["manifest_version"],
            "MODEL_MANIFEST_PATH": "tools/model-manifest.json",
            "MODEL_MANIFEST_URI": _require(args.manifest_uri, "manifest-uri"),
        }
    )
    _check_function(
        project,
        region,
        function,
        aes_secret,
        device_secret,
        args.secret_version,
        expected_env,
        manifest_sha,
    )
    print("Function verification passed: Gen 2, v2-only defaults, and Secret Manager bindings")


def _manifest_check(args: argparse.Namespace) -> None:
    manifest, digest = _load_required_manifest(args)
    print(
        f"Model manifest valid: version={manifest['manifest_version']} "
        f"files={len(manifest['files'])} sha256={digest}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser("preflight", help="check resources before deployment")
    _add_common_arguments(preflight)
    preflight.add_argument("--configure-ttl", action="store_true")
    preflight.add_argument("--configure-bucket", action="store_true")
    preflight.add_argument("--verify-model-objects", action="store_true")
    preflight.add_argument("--skip-secret-metadata", action="store_true")

    function = subparsers.add_parser("function", help="verify the deployed Gen 2 function")
    _add_common_arguments(function)

    manifest = subparsers.add_parser("manifest", help="validate a local model manifest")
    manifest.add_argument("--manifest", required=True, type=Path)
    manifest.set_defaults(project="")

    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            _preflight(args)
        elif args.command == "function":
            _function_check(args)
        else:
            _manifest_check(args)
    except CheckError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
