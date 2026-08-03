#!/usr/bin/env python3
"""Host-only assertions for the bounded firmware follow-up."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    config_h = (ROOT / "include" / "config.h").read_text(encoding="utf-8")
    config_cpp = (ROOT / "src" / "config.cpp").read_text(encoding="utf-8")
    watchdog_h = (ROOT / "include" / "watchdog.h").read_text(encoding="utf-8")
    watchdog_cpp = (ROOT / "src" / "watchdog.cpp").read_text(encoding="utf-8")
    main_cpp = (ROOT / "src" / "main.cpp").read_text(encoding="utf-8")
    relay_cpp = (ROOT / "src" / "relay.cpp").read_text(encoding="utf-8")
    crypto_test = (ROOT / "test" / "test_crypto_gcm" / "test_main.cpp").read_text(
        encoding="utf-8"
    )
    aes_vector = (ROOT / "test" / "aes_gcm_vector.json").read_text(encoding="utf-8")
    platformio = (ROOT / "platformio.ini").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
    valid_ids = ("A", "cam-front-door", "9_device", "a" * 64)
    invalid_ids = ("", ".cam", "_cam", "-cam", "cam.id", "cam:id", "a" * 65)
    assert all(pattern.fullmatch(value) for value in valid_ids)
    assert not any(pattern.fullmatch(value) for value in invalid_ids)

    assert 'kHealthPath = "/api/health"' in config_h
    assert 'PROVISION SET DEVICE_ID [A-Za-z0-9][A-Za-z0-9_-]{0,63}' in config_cpp
    assert 'device_id must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}' in config_cpp
    assert "`/api/health`" in readme
    assert "to `" + "/health`" not in readme

    assert "#include <esp_task_wdt.h>" in watchdog_h
    assert "esp_task_wdt_config_t" in watchdog_cpp
    assert "esp_task_wdt_init(&config)" in watchdog_cpp
    assert "esp_task_wdt_add(nullptr)" in watchdog_cpp
    assert "esp_task_wdt_status(nullptr)" in watchdog_cpp
    assert "initializeWatchdog()" in main_cpp
    assert "watchdogReady()" in main_cpp
    assert "relay.off();" in main_cpp

    assert "case 2:" not in config_cpp
    assert "case 12:" not in config_cpp
    assert "case 15:" not in config_cpp
    assert "pin_ == 2" not in relay_cpp
    assert "pin_ == 12" not in relay_cpp
    assert "pin_ == 15" not in relay_cpp

    assert "#define SAHL_PRODUCTION 0" in config_h
    assert "SAHL_REQUIRE_FLASH_ENCRYPTION" in config_h
    assert "SAHL_PRODUCTION is blocked until authenticated time trust" in config_h
    assert "esp_flash_encryption_enabled()" in config_cpp
    assert "if (!secureStorageReady())" in config_cpp
    assert "NVS-only secrets are not production protection" in config_cpp
    assert "SAHL_PRODUCTION=0" in platformio
    assert "SAHL_REQUIRE_FLASH_ENCRYPTION=1" in platformio
    assert "test_build_project_src = no" in platformio
    assert "unauthenticated SNTP" in readme
    assert "NVS alone is not production secret" in readme

    assert "#include <mbedtls/gcm.h>" in crypto_test
    assert "smart-ai-home-lock-v1" in crypto_test
    assert "nonce || tag || ciphertext" in crypto_test
    assert "nonce_hex" in aes_vector
    print("firmware follow-up static checks: PASS")


if __name__ == "__main__":
    main()
