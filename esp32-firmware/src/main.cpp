#include <Arduino.h>
#include <WiFi.h>

#include <time.h>

#include <vector>

#include "camera.h"
#include "config.h"
#include "crypto.h"
#include "liveness.h"
#include "protocol.h"
#include "relay.h"
#include "transport.h"
#include "watchdog.h"

namespace {

ConfigStore configStore;
Camera camera;
LivenessFilter liveness;
Relay relay;
Transport transport;
bool cameraReady = false;
uint32_t lastReconnectAttempt = 0;
String serialLine;
bool serialLineOverflow = false;

bool unixTimeIsValid() {
  const time_t now = time(nullptr);
  return now >= kMinimumValidUnixTime;
}

bool waitForValidNtp(const DeviceConfig &config) {
  if (unixTimeIsValid()) {
    return true;
  }
  configTime(0, 0, config.ntpServer.c_str());
  const uint32_t start = millis();
  while (!unixTimeIsValid() && millis() - start < kNtpWaitMs) {
    delay(250);
    feedWatchdog();
  }
  return unixTimeIsValid();
}

bool prepareNetwork(const DeviceConfig &config) {
  if (!transport.ensureWifi(config)) {
    Serial.println("Wi-Fi unavailable; relay remains off");
    return false;
  }
  if (!waitForValidNtp(config)) {
    Serial.println("NTP validity timeout; relay remains off");
    return false;
  }
  return true;
}

void pulseRelay(const DeviceConfig &config) {
  relay.on();
  const uint32_t start = millis();
  while (millis() - start < config.relayPulseMs) {
    delay(10);
    feedWatchdog();
  }
  relay.off();
}

void performUnlock() {
  relay.off();
  const DeviceConfig &config = configStore.config();
  String reason;
  if (!config.valid(&reason)) {
    Serial.print("Unlock blocked: ");
    Serial.println(reason);
    return;
  }
  if (!prepareNetwork(config)) {
    return;
  }
  if (!cameraReady) {
    cameraReady = camera.begin();
    if (!cameraReady) {
      Serial.println("Camera initialization failed; relay remains off");
      return;
    }
  }

  LivenessResult livenessResult;
  if (!liveness.check(camera, livenessResult)) {
    Serial.print("Unlock blocked by fresh-frame prefilter: ");
    Serial.println(livenessResult.reason);
    relay.off();
    return;
  }

  camera_fb_t *frame = camera.capture();
  if (frame == nullptr || frame->len > kMaxUnlockJpegBytes) {
    if (frame != nullptr) {
      camera.release(frame);
    }
    Serial.println("Unlock blocked: invalid or oversized JPEG");
    relay.off();
    return;
  }

  std::vector<uint8_t> encryptedBody;
  std::string cryptoError;
  const bool encrypted = Crypto::encryptAes256Gcm(
      frame->buf, frame->len, config.aesKey, encryptedBody, cryptoError);
  camera.release(frame);
  if (!encrypted) {
    Serial.print("Unlock blocked by encryption: ");
    Serial.println(cryptoError.c_str());
    relay.off();
    return;
  }

  const time_t timestamp = time(nullptr);
  if (timestamp < kMinimumValidUnixTime) {
    Serial.println("Unlock blocked: timestamp became invalid");
    relay.off();
    return;
  }
  Protocol::SignedHeaders headers;
  std::string protocolError;
  if (!Protocol::buildUnlockHeaders(
          config.deviceId, static_cast<uint64_t>(timestamp), config.hmacKey,
          encryptedBody.data(), encryptedBody.size(), headers,
          protocolError)) {
    Serial.print("Unlock blocked by protocol signing: ");
    Serial.println(protocolError.c_str());
    relay.off();
    return;
  }

  const UnlockTransportResult result =
      transport.postUnlock(config, encryptedBody, headers);
  relay.off();
  const bool exactUnlock =
      result.tlsSucceeded && result.httpStatus == 200 && result.jsonParsed &&
      result.response.protocolVersion == 2 &&
      result.response.status == "UNLOCK";

  Serial.print("Unlock HTTP status: ");
  Serial.println(result.httpStatus);
  if (result.state == RequestState::Uncertain) {
    Serial.println("Unlock packet outcome uncertain; no retry performed");
  }
  if (!result.jsonParsed && result.error.length() != 0) {
    Serial.print("Unlock response rejected: ");
    Serial.println(result.error);
  }
  if (exactUnlock) {
    Serial.println("Exact v2 UNLOCK response accepted; pulsing relay");
    pulseRelay(config);
  } else {
    // This is also executed for every non-200, malformed, stale-protocol, or
    // non-UNLOCK response. Fail closed is the only relay default.
    relay.off();
    Serial.println("Unlock not authorized; relay remains off");
  }
}

void performHealth() {
  relay.off();
  const DeviceConfig &config = configStore.config();
  String reason;
  if (!config.valid(&reason)) {
    Serial.print("Health blocked: ");
    Serial.println(reason);
    return;
  }
  if (!prepareNetwork(config)) {
    return;
  }
  const time_t timestamp = time(nullptr);
  Protocol::SignedHeaders headers;
  std::string protocolError;
  if (!Protocol::buildHealthHeaders(
          config.deviceId, static_cast<uint64_t>(timestamp), config.hmacKey,
          headers, protocolError)) {
    Serial.print("Health signing failed: ");
    Serial.println(protocolError.c_str());
    return;
  }
  const HealthTransportResult result = transport.getHealth(config, headers);
  relay.off();
  Serial.print("Health HTTP status: ");
  Serial.println(result.httpStatus);
  if (result.state == RequestState::Uncertain) {
    Serial.println("Health request outcome uncertain; no retry performed");
  }
  if (result.error.length() != 0) {
    Serial.println(result.error);
  } else {
    Serial.println("Health response received");
  }
}

void serviceSerial() {
  while (Serial.available()) {
    const char character = static_cast<char>(Serial.read());
    if (character != '\n') {
      if (!serialLineOverflow) {
        if (serialLine.length() >= kMaxProvisioningLine) {
          serialLineOverflow = true;
        } else {
          serialLine += character;
        }
      }
      continue;
    }

    if (serialLineOverflow) {
      Serial.println("ERR command too long");
    } else {
      const ConsoleCommand command =
          configStore.handleSerialLine(serialLine, Serial);
      switch (command) {
        case ConsoleCommand::Unlock:
          performUnlock();
          break;
        case ConsoleCommand::Health:
          performHealth();
          break;
        case ConsoleCommand::Reboot:
          relay.off();
          delay(50);
          ESP.restart();
          break;
        case ConsoleCommand::None:
          break;
      }
    }
    serialLine = "";
    serialLineOverflow = false;
    return;
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(50);

  // Establish the safe physical state before reading any network or NVS
  // configuration. A provisioned configuration can replace the pin after a
  // reboot, but every boot starts with the relay de-energized.
  relay.begin(kDefaultRelayPin, kDefaultRelayActiveHigh);
  if (!initializeWatchdog()) {
    Serial.println("Task watchdog initialization failed; relay remains off");
    relay.off();
    return;
  }
  configStore.load();
  const DeviceConfig &config = configStore.config();
  if (config.valid()) {
    relay.begin(config.relayPin, config.relayActiveHigh);
    cameraReady = camera.begin();
    if (!cameraReady) {
      Serial.println("Camera initialization failed; unlocks are blocked");
    }
    WiFi.persistent(false);
    prepareNetwork(config);
  } else {
    relay.off();
    Serial.println("Firmware is not provisioned; relay remains off");
  }
  configStore.printStatus(Serial);
  configStore.printHelp(Serial);
}

void loop() {
  if (!watchdogReady()) {
    relay.off();
    delay(1000);
    return;
  }
  feedWatchdog();
  serviceSerial();

  const DeviceConfig &config = configStore.config();
  if (config.valid() && WiFi.status() != WL_CONNECTED &&
      millis() - lastReconnectAttempt >= 5000) {
    relay.off();
    lastReconnectAttempt = millis();
    transport.ensureWifi(config);
    if (WiFi.status() == WL_CONNECTED) {
      waitForValidNtp(config);
    }
  }
  if (!config.valid()) {
    relay.off();
  }
  delay(10);
}
