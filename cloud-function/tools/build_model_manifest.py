#!/usr/bin/env python3
"""Build a deterministic, non-secret manifest for the buffalo_l model pack.

The model binaries are intentionally not kept in this repository.  Run this
tool from a controlled model staging directory, review the resulting JSON, and
publish the manifest and the exact same binaries to the private model bucket.
The deployment preflight consumes the resulting file and fails closed on any
missing or malformed size/hash entry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path


MODEL_FILES = ("det_10g.onnx", "w600k_r50.onnx", "2d106det.onnx")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as model_file:
        for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(model_dir: Path, version: str, artifact_prefix: str) -> dict:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must contain only letters, numbers, '.', '_' or '-'")
    if (
        not artifact_prefix
        or artifact_prefix.startswith("/")
        or "\\" in artifact_prefix
        or any(part in {"", ".", ".."} for part in artifact_prefix.split("/"))
    ):
        raise ValueError("artifact_prefix must be a non-empty relative path")

    files = []
    for name in MODEL_FILES:
        path = model_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"model file is missing: {path}")
        size = path.stat().st_size
        if size <= 0:
            raise ValueError(f"model file is empty: {path}")
        files.append(
            {
                "name": name,
                "expected_size_bytes": size,
                "sha256": _sha256(path),
            }
        )

    return {
        "schema_version": 1,
        "manifest_version": version,
        "model_name": "buffalo_l",
        "artifact_prefix": artifact_prefix.rstrip("/"),
        "verification_status": "verified-at-build-time",
        "files": files,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--artifact-prefix", default="models/buffalo_l", help="relative GCS prefix"
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        manifest = build_manifest(args.model_dir, args.version, args.artifact_prefix)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as manifest_file:
            json.dump(manifest, manifest_file, indent=2, sort_keys=False)
            manifest_file.write("\n")
    except (OSError, ValueError, FileNotFoundError) as exc:
        print(f"ERROR: could not build model manifest: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote non-secret model manifest: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
