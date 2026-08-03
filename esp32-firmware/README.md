# ESP32-CAM firmware lane

This is the Day 5-6 firmware lane for an AI Thinker ESP32-CAM. It is a
PlatformIO Arduino project pinned to `espressif32@6.9.0` (Arduino-ESP32 3.0.7)
and uses only the ESP32 core's bundled mbedTLS for cryptography.

## Hardware and wiring

* Board: AI Thinker ESP32-CAM, with PSRAM recommended and a 4 MB flash
  configuration.
* Camera pins are the official AI Thinker map in `src/camera.cpp`.
* The relay control signal is GPIO13 by default. GPIO13 is shared with the
  micro-SD interface, so do not use the SD socket in this firmware lane.
  Provisioning accepts only GPIO4, GPIO13, or GPIO14; strapping pins GPIO2,
  GPIO12, and GPIO15 are deliberately rejected.
* Connect the relay module input to GPIO13 and its ground to ESP32 ground.
  Power the relay from an appropriate externally regulated supply; do not
  power an inductive load directly from an ESP32 GPIO. Use a transistor or a
  relay module with flyback protection, a hardware pull resistor that holds
  the driver inactive during reset, and common ground.
* The default is active-high. `RELAY_ACTIVE_HIGH=0` supports an active-low
  module. A boot, configuration, camera, Wi-Fi, time, TLS, HTTP, JSON, or
  protocol failure always leaves the relay off.

The firmware has no OTA path. The partition table contains one factory app,
not OTA slots, because this lock lane deliberately requires a physical serial
flash/review path and does not implement remote update authentication or
rollback policy.

## Provisioning

No production Wi-Fi credentials, CA, AES key, HMAC key, or endpoint is
compiled into the production firmware. The default PlatformIO environment is explicitly
`SAHL_PRODUCTION=0` and is development-only: settings are stored in the
`sahl` Preferences/NVS namespace, but NVS alone is not production secret
protection. Open the serial console at 115200 baud and use commands such as:

```text
PROVISION SET DEVICE_ID cam-front-door
PROVISION SET WIFI_SSID my-network
PROVISION SET WIFI_PASSWORD my-password
PROVISION SET ENDPOINT_HOST lock.example.test
PROVISION SET ENDPOINT_PORT 443
PROVISION SET CA_CERT -----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----
PROVISION SET AES_KEY_HEX <64 hex characters>
PROVISION SET HMAC_KEY_HEX <64 hex characters>
PROVISION SET RELAY_ACTIVE_HIGH 1
PROVISION SET RELAY_PULSE_MS 750
PROVISION SAVE
PROVISION REBOOT
```

Device IDs must match the approved v2 syntax
`[A-Za-z0-9][A-Za-z0-9_-]{0,63}`: the first character is alphanumeric and the
remaining characters may be alphanumeric, `_`, or `-`. Dots and colons are not
accepted.

`PROVISION STATUS` reports only whether sensitive fields are set; it never
prints passwords, keys, or certificate data. Values are staged in RAM until
`PROVISION SAVE`, and configuration is validated before it is written. The
serial console is a physical provisioning interface: protect access to it and
erase/reprovision the NVS before transferring a device. `secrets.example.ini`
contains placeholders only.

## Request protocol

An unlock command is issued with `UNLOCK` on the serial console (a product
trigger can call the same `performUnlock()` path later). The camera captures
three JPEG frames first. The prefilter is only a small freshness/motion
heuristic: capture timestamps must increase and sampled JPEG bytes must change.
It is not a facial liveness detector. If three fresh frames cannot be
established, the request is rejected and the relay remains off.

The encrypted raw binary body is unchanged:

```text
nonce (12 bytes) || GCM tag (16 bytes) || ciphertext
```

AES-256-GCM uses AAD `smart-ai-home-lock-v1`. The AES key and HMAC key are
separate 32-byte values loaded from NVS. The v2 unlock request is one raw
binary POST to `/api/unlock` with:

```text
X-Protocol-Version: 2
X-Device-ID: <device_id>
X-Timestamp: <Unix seconds from finite development-only SNTP synchronization>
X-Request-Nonce: <16 random bytes as 32 lowercase hex characters>
X-Request-Signature: <lowercase HMAC-SHA256>
```

The signature input is exactly:

```text
SAHL-V2
POST
/api/unlock

<device_id>
<timestamp>
<request_nonce_hex>
<sha256(raw_body)_hex>
```

TLS validates the provisioned CA; there is no insecure TLS fallback. TLS,
HTTP, and NTP waits are finite. Wi-Fi reconnect uses bounded backoff. A
negative result from the single unlock POST is treated as an uncertain packet
and is never retried automatically.

The current time bootstrap is unauthenticated SNTP. Therefore any build with
`SAHL_PRODUCTION=1` is intentionally rejected at compile time until an
approved authenticated or multi-source time-trust implementation exists.
Do not deploy the development build as production or treat a valid SNTP clock
as an authenticated security signal. A future production build must also pass
the `SAHL_REQUIRE_FLASH_ENCRYPTION=1` runtime flash-encryption gate or provide
an approved secure-element integration; ordinary NVS is never represented as
production secret storage.

The relay is pulsed only when all of these are true: TLS completed, HTTP status
is exactly 200, the bounded body is valid JSON, `protocol_version` is exactly
2, and `status` is exactly the string `UNLOCK`. Health support is available
with `HEALTH`; it sends a non-actuating GET to the public deployed
`/api/health` route and never controls the relay. The public route accepts and
ignores the v2 signing headers, which the firmware preserves for consistent
transport observability.

The current Arduino task is explicitly subscribed to the ESP32 task watchdog
during setup and verified with `esp_task_wdt_status(nullptr)`. A watchdog
initialization or subscription failure leaves the relay off and keeps the
firmware blocked; normal bounded waits feed the watchdog, while a stalled task
fails closed through reset.

## Build and checks

```bash
pio run -d esp32-firmware
pio device monitor -d esp32-firmware
```

`tools/test_protocol_vectors.py` is a host-only standard-library check of the
canonical request, lowercase HMAC, and `nonce || tag || ciphertext` envelope
shape. PlatformIO and an attached ESP32-CAM/relay were unavailable during
implementation, so no hardware, camera, TLS, relay, or cloud integration
validation is claimed. The firmware source/API is kept aligned with the
pinned Arduino-ESP32 3.x APIs and the host golden vector can be run without
PlatformIO:

```bash
python3 esp32-firmware/tools/test_protocol_vectors.py
python3 esp32-firmware/tools/test_firmware_static.py
```

When PlatformIO is available, the deterministic mbedTLS AES-256-GCM packet
vector can be run on the board with:

```bash
pio test -d esp32-firmware -e ai-thinker-esp32-cam -f test_crypto_gcm
```
