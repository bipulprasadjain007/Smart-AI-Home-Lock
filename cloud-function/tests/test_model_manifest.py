"""Tests for the model artifact manifest shared by build and deployment."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"


def _load_tool(name: str):
    path = TOOLS_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_model_manifest = _load_tool("build_model_manifest")
verify_infrastructure = _load_tool("verify_infrastructure")


def _model_dir(tmp_path: Path) -> Path:
    model_dir = tmp_path / "buffalo_l"
    model_dir.mkdir()
    for name in build_model_manifest.MODEL_FILES:
        (model_dir / name).write_bytes(f"artifact:{name}".encode("utf-8"))
    return model_dir


def test_generated_manifest_passes_deployment_validation(tmp_path):
    manifest = build_model_manifest.build_manifest(
        _model_dir(tmp_path), "buffalo_l-test-v1", "models/buffalo_l"
    )

    verify_infrastructure._validate_manifest(manifest)
    assert manifest["verification_status"] == "verified-at-build-time"
    assert all(item["expected_size_bytes"] > 0 for item in manifest["files"])


def test_pending_manifest_is_rejected(tmp_path):
    manifest = build_model_manifest.build_manifest(
        _model_dir(tmp_path), "buffalo_l-test-v1", "models/buffalo_l"
    )
    manifest["verification_status"] = "pending-live-verification"

    with pytest.raises(
        verify_infrastructure.CheckError, match="verified-at-build-time"
    ):
        verify_infrastructure._validate_manifest(manifest)


@pytest.mark.parametrize("prefix", ["/models/buffalo_l", "models//pack", "a/../b", r"a\\b"])
def test_generator_rejects_unsafe_artifact_prefix(tmp_path, prefix):
    with pytest.raises(ValueError, match="artifact_prefix"):
        build_model_manifest.build_manifest(
            _model_dir(tmp_path), "buffalo_l-test-v1", prefix
        )
