# Smart AI Home Lock

Smart AI Home Lock is a fail-closed ESP32-CAM access-control system backed by
a Python cloud service. Face and PIN decisions are returned only to
authenticated devices, while administrative operations require a Firebase
administrator token.

## Repository layout

- `cloud-function/` contains the Flask/Functions Framework service, deployment
  preflight, model-manifest verification, and the automated test suite.
- `esp32-firmware/` contains the pinned PlatformIO firmware, host protocol
  checks, and an on-device AES-GCM test vector.
- `docs/deployment.md` contains the production and local deployment procedure.
- Root `main.py` is a migration guard. Root `pin.py` is a local encrypted-packet
  helper; neither is the production service entrypoint.

## Security boundary

The device sends AES-256-GCM payloads and protocol-v2 HMAC headers. The cloud
service checks device authorization, clock freshness, user scope, and a
transactional replay reservation before processing an unlock request. The
firmware pulses the relay only for an exact HTTP 200 response containing
`protocol_version: 2` and `status: "UNLOCK"`.

Boot-time clock establishment is fail closed. SNTP supplies only enough rough
time for TLS certificate validation; `/api/device_time` then returns a
device-authenticated, challenge-bound timestamp. Production firmware also
requires ESP32 flash encryption at runtime before stored credentials are used.

## Local validation

Python 3.12 and a C/C++ compiler are required because InsightFace 0.7.3 builds
a native extension.

```bash
python3 -m venv .venv
source .venv/bin/activate
CC=gcc CXX=g++ pip install -r cloud-function/tests/requirements-test.txt
cd cloud-function
pytest -q
cd ..
python3 esp32-firmware/tools/test_protocol_vectors.py
python3 esp32-firmware/tools/test_firmware_static.py
python3 -m compileall -q cloud-function main.py pin.py esp32-firmware/tools
bash -n cloud-function/deploy.sh cloud-function/tools/verify_infrastructure.sh
```

Build both firmware policies with PlatformIO:

```bash
pio run -d esp32-firmware -e ai-thinker-esp32-cam
pio run -d esp32-firmware -e ai-thinker-esp32-cam-production
```

The production image will still refuse to operate on a device whose flash
encryption eFuse is not enabled. Camera, TLS, relay polarity, and power-path
validation require the target ESP32-CAM hardware.

## Deployment

Review `docs/deployment.md`, provision Secret Manager and private model
artifacts, generate the ignored `cloud-function/tools/model-manifest.json` from
those exact artifacts, then run:

```bash
bash cloud-function/deploy.sh
bash cloud-function/tools/verify_infrastructure.sh
```

Deployment verification needs authenticated `gcloud` access to the target
project. No production credential belongs in this repository.
