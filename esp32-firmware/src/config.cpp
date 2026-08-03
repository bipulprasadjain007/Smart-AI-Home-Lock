#include "config.h"

#include <Preferences.h>
#include <esp_flash_encrypt.h>

#include <cstring>

#include "crypto.h"

namespace {

constexpr const char *kPreferencesNamespace = "sahl";

bool isValidDeviceId(const String &value) {
  if (value.length() == 0 || value.length() > 64) {
    return false;
  }
  const char first = value[0];
  if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') ||
        (first >= '0' && first <= '9'))) {
    return false;
  }
  for (size_t i = 1; i < value.length(); ++i) {
    const char c = value[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '_')) {
      return false;
    }
  }
  return true;
}

bool isSafeHost(const String &value) {
  if (value.length() == 0 || value.length() > 253) {
    return false;
  }
  for (size_t i = 0; i < value.length(); ++i) {
    const char c = value[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '.')) {
      return false;
    }
  }
  return true;
}

bool isRelayPinAllowed(uint8_t pin) {
  // Only non-strapping, non-camera output pins validated for this board are
  // accepted. GPIO2/12/15 are intentionally excluded because they are
  // strapping pins; GPIO13 remains the documented default.
  switch (pin) {
    case 4:
    case 13:
    case 14:
      return true;
    default:
      return false;
  }
}

bool hasNonZeroKey(const uint8_t *key, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    if (key[i] != 0) {
      return true;
    }
  }
  return false;
}

void printSetState(Stream &out, const char *name, bool set) {
  out.print(name);
  out.println(set ? "=SET" : "=MISSING");
}

}  // namespace

bool secureStorageReady() {
#if SAHL_PRODUCTION
#if SAHL_REQUIRE_FLASH_ENCRYPTION
  return esp_flash_encryption_enabled();
#else
  return false;
#endif
#else
  // Development builds intentionally retain the existing NVS provisioning
  // path, but status output identifies it as non-production.
  return true;
#endif
}

bool DeviceConfig::valid(String *reason) const {
  if (reason != nullptr) {
    reason->remove(0);
  }
  auto fail = [reason](const char *message) {
    if (reason != nullptr) {
      *reason = message;
    }
    return false;
  };

  if (!isValidDeviceId(deviceId)) {
    return fail("device_id must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}");
  }
#if SAHL_PRODUCTION
  if (!secureStorageReady()) {
    return fail("production requires encrypted flash; no secure element is configured");
  }
#endif
  if (wifiSsid.length() == 0 || wifiSsid.length() > 32) {
    return fail("wifi_ssid is missing or too long");
  }
  if (wifiPassword.length() > 63) {
    return fail("wifi_password is too long");
  }
  if (!isSafeHost(endpointHost)) {
    return fail("endpoint_host is invalid");
  }
  if (endpointPort == 0) {
    return fail("endpoint_port is invalid");
  }
  if (caCertificate.length() < 64 ||
      caCertificate.indexOf("BEGIN CERTIFICATE") < 0 ||
      caCertificate.indexOf("END CERTIFICATE") < 0) {
    return fail("ca_certificate is missing or is not PEM");
  }
  if (!isSafeHost(ntpServer)) {
    return fail("ntp_server is invalid");
  }
  if (!aesKeyConfigured || !hasNonZeroKey(aesKey, kAesKeyBytes)) {
    return fail("aes_key is missing");
  }
  if (!hmacKeyConfigured || !hasNonZeroKey(hmacKey, kHmacKeyBytes)) {
    return fail("hmac_key is missing");
  }
  if (!isRelayPinAllowed(relayPin)) {
    return fail("relay_pin conflicts with the camera or serial pins");
  }
  if (relayPulseMs < 100 || relayPulseMs > 5000) {
    return fail("relay_pulse_ms must be between 100 and 5000");
  }
  return true;
}

bool ConfigStore::load() {
  config_ = DeviceConfig{};

  Preferences preferences;
  if (!preferences.begin(kPreferencesNamespace, true)) {
    return false;
  }

  config_.deviceId = preferences.getString("device_id", "");
  config_.wifiSsid = preferences.getString("wifi_ssid", "");
  config_.wifiPassword = preferences.getString("wifi_password", "");
  config_.endpointHost = preferences.getString("endpoint_host", "");
  config_.endpointPort =
      preferences.getUShort("endpoint_port", kDefaultEndpointPort);
  config_.caCertificate = preferences.getString("ca_certificate", "");
  config_.ntpServer = preferences.getString("ntp_server", kDefaultNtpServer);
  config_.relayPin = preferences.getUChar("relay_pin", kDefaultRelayPin);
  config_.relayActiveHigh =
      preferences.getBool("relay_active_high", kDefaultRelayActiveHigh);
  config_.relayPulseMs =
      preferences.getULong("relay_pulse_ms", kDefaultRelayPulseMs);

  config_.aesKeyConfigured =
      preferences.getBytesLength("aes_key") == kAesKeyBytes &&
      preferences.getBytes("aes_key", config_.aesKey, kAesKeyBytes) ==
          kAesKeyBytes;
  config_.hmacKeyConfigured =
      preferences.getBytesLength("hmac_key") == kHmacKeyBytes &&
      preferences.getBytes("hmac_key", config_.hmacKey, kHmacKeyBytes) ==
          kHmacKeyBytes;

  preferences.end();
  return true;
}

bool ConfigStore::save(Stream &out) {
  String reason;
  if (!config_.valid(&reason)) {
    out.print("ERR config invalid: ");
    out.println(reason);
    return false;
  }

  Preferences preferences;
  if (!preferences.begin(kPreferencesNamespace, false)) {
    out.println("ERR NVS open failed");
    return false;
  }

  bool ok = true;
  ok = preferences.putString("device_id", config_.deviceId) > 0 && ok;
  ok = preferences.putString("wifi_ssid", config_.wifiSsid) > 0 && ok;
  ok = preferences.putString("wifi_password", config_.wifiPassword) > 0 && ok;
  ok = preferences.putString("endpoint_host", config_.endpointHost) > 0 && ok;
  ok = preferences.putUShort("endpoint_port", config_.endpointPort) ==
           sizeof(config_.endpointPort) &&
       ok;
  ok = preferences.putString("ca_certificate", config_.caCertificate) > 0 &&
       ok;
  ok = preferences.putString("ntp_server", config_.ntpServer) > 0 && ok;
  ok = preferences.putBytes("aes_key", config_.aesKey, kAesKeyBytes) ==
           kAesKeyBytes &&
       ok;
  ok = preferences.putBytes("hmac_key", config_.hmacKey, kHmacKeyBytes) ==
           kHmacKeyBytes &&
       ok;
  ok = preferences.putUChar("relay_pin", config_.relayPin) == 1 && ok;
  ok = preferences.putBool("relay_active_high", config_.relayActiveHigh) == 1 &&
       ok;
  ok = preferences.putULong("relay_pulse_ms", config_.relayPulseMs) ==
           sizeof(config_.relayPulseMs) &&
       ok;
  preferences.end();

  if (ok) {
    out.println("OK configuration saved; reboot required");
  } else {
    out.println("ERR configuration save failed");
  }
  return ok;
}

bool ConfigStore::clear(Stream &out) {
  Preferences preferences;
  if (!preferences.begin(kPreferencesNamespace, false)) {
    out.println("ERR NVS open failed");
    return false;
  }
  const bool ok = preferences.clear();
  preferences.end();
  config_ = DeviceConfig{};
  out.println(ok ? "OK configuration cleared; reboot required"
                 : "ERR configuration clear failed");
  return ok;
}

void ConfigStore::printStatus(Stream &out) const {
  String reason;
  out.print("device_id=");
  out.println(config_.deviceId.length() ? config_.deviceId : "MISSING");
  out.print("endpoint_host=");
  out.println(config_.endpointHost.length() ? config_.endpointHost : "MISSING");
  out.print("endpoint_port=");
  out.println(config_.endpointPort);
  printSetState(out, "wifi_ssid", config_.wifiSsid.length() != 0);
  printSetState(out, "wifi_password", config_.wifiPassword.length() != 0);
  printSetState(out, "ca_certificate", config_.caCertificate.length() != 0);
  printSetState(out, "aes_key", config_.aesKeyConfigured);
  printSetState(out, "hmac_key", config_.hmacKeyConfigured);
  out.print("relay_pin=");
  out.println(config_.relayPin);
  out.print("relay_active_high=");
  out.println(config_.relayActiveHigh ? "1" : "0");
  out.print("valid=");
  out.println(config_.valid(&reason) ? "yes" : "no");
#if SAHL_PRODUCTION
  out.print("secure_storage=");
  out.println(secureStorageReady() ? "FLASH_ENCRYPTION" : "MISSING");
#else
  out.println("secure_storage=DEVELOPMENT_ONLY_NVS");
  out.println("WARNING: NVS-only secrets are not production protection");
#endif
  if (reason.length() != 0) {
    out.print("reason=");
    out.println(reason);
  }
}

void ConfigStore::printHelp(Stream &out) const {
  out.println("UNLOCK                         capture and send one unlock packet");
  out.println("HEALTH                         send one signed health request");
  out.println("PROVISION STATUS               show non-secret configuration state");
  out.println("PROVISION SET DEVICE_ID [A-Za-z0-9][A-Za-z0-9_-]{0,63}");
  out.println("PROVISION SET WIFI_SSID value");
  out.println("PROVISION SET WIFI_PASSWORD value");
  out.println("PROVISION SET ENDPOINT_HOST value");
  out.println("PROVISION SET ENDPOINT_PORT 443");
  out.println("PROVISION SET CA_CERT escaped-PEM (use \\n for line breaks)");
  out.println("PROVISION SET AES_KEY_HEX 64-hex-characters");
  out.println("PROVISION SET HMAC_KEY_HEX 64-hex-characters");
  out.println("PROVISION SET RELAY_ACTIVE_HIGH 0|1");
  out.println("PROVISION SET RELAY_PULSE_MS 100..5000");
  out.println("PROVISION SAVE                 persist only after validation");
  out.println("PROVISION CLEAR                erase all firmware NVS settings");
  out.println("PROVISION REBOOT               reboot after provisioning");
}

bool ConfigStore::parsePort(const String &value, uint16_t &port) const {
  if (value.length() == 0 || value.length() > 5) {
    return false;
  }
  uint32_t parsed = 0;
  if (!parseUint32(value, parsed) || parsed == 0 || parsed > 65535) {
    return false;
  }
  port = static_cast<uint16_t>(parsed);
  return true;
}

bool ConfigStore::parseBool(const String &value, bool &result) const {
  if (value == "1" || value == "true" || value == "TRUE") {
    result = true;
    return true;
  }
  if (value == "0" || value == "false" || value == "FALSE") {
    result = false;
    return true;
  }
  return false;
}

bool ConfigStore::parseUint32(const String &value, uint32_t &result) const {
  if (value.length() == 0 || value.length() > 10) {
    return false;
  }
  uint64_t parsed = 0;
  for (size_t i = 0; i < value.length(); ++i) {
    if (value[i] < '0' || value[i] > '9') {
      return false;
    }
    parsed = parsed * 10 + static_cast<uint32_t>(value[i] - '0');
    if (parsed > 0xFFFFFFFFULL) {
      return false;
    }
  }
  result = static_cast<uint32_t>(parsed);
  return true;
}

bool ConfigStore::setField(const String &key, String value, Stream &out) {
  if (value.length() > kMaxProvisioningLine) {
    out.println("ERR value too long");
    return false;
  }

  if (key == "DEVICE_ID") {
    config_.deviceId = value;
  } else if (key == "WIFI_SSID") {
    config_.wifiSsid = value;
  } else if (key == "WIFI_PASSWORD") {
    config_.wifiPassword = value;
  } else if (key == "ENDPOINT_HOST") {
    config_.endpointHost = value;
  } else if (key == "ENDPOINT_PORT") {
    uint16_t port = 0;
    if (!parsePort(value, port)) {
      out.println("ERR endpoint port");
      return false;
    }
    config_.endpointPort = port;
  } else if (key == "CA_CERT") {
    value.replace("\\n", "\n");
    config_.caCertificate = value;
  } else if (key == "AES_KEY_HEX") {
    if (!Crypto::parseHex(value.c_str(), value.length(), config_.aesKey,
                          kAesKeyBytes)) {
      out.println("ERR AES key must be exactly 64 hex characters");
      return false;
    }
    config_.aesKeyConfigured = true;
  } else if (key == "HMAC_KEY_HEX") {
    if (!Crypto::parseHex(value.c_str(), value.length(), config_.hmacKey,
                          kHmacKeyBytes)) {
      out.println("ERR HMAC key must be exactly 64 hex characters");
      return false;
    }
    config_.hmacKeyConfigured = true;
  } else if (key == "RELAY_ACTIVE_HIGH") {
    bool activeHigh = false;
    if (!parseBool(value, activeHigh)) {
      out.println("ERR relay active level must be 0 or 1");
      return false;
    }
    config_.relayActiveHigh = activeHigh;
  } else if (key == "RELAY_PULSE_MS") {
    uint32_t pulseMs = 0;
    if (!parseUint32(value, pulseMs)) {
      out.println("ERR relay pulse duration");
      return false;
    }
    config_.relayPulseMs = pulseMs;
  } else {
    out.println("ERR unknown provisioning field");
    return false;
  }

  out.println("OK value staged; use PROVISION SAVE");
  return true;
}

ConsoleCommand ConfigStore::handleSerialLine(const String &input, Stream &out) {
  if (input.length() > kMaxProvisioningLine) {
    out.println("ERR command too long");
    return ConsoleCommand::None;
  }

  String line = input;
  line.trim();
  if (line.length() == 0) {
    return ConsoleCommand::None;
  }
  if (line == "UNLOCK") {
    return ConsoleCommand::Unlock;
  }
  if (line == "HEALTH") {
    return ConsoleCommand::Health;
  }
  if (!line.startsWith("PROVISION")) {
    out.println("ERR unknown command; use PROVISION HELP");
    return ConsoleCommand::None;
  }

  String command = line.substring(strlen("PROVISION"));
  command.trim();
  if (command == "HELP") {
    printHelp(out);
    return ConsoleCommand::None;
  }
  if (command == "STATUS") {
    printStatus(out);
    return ConsoleCommand::None;
  }
  if (command == "SAVE") {
    save(out);
    return ConsoleCommand::None;
  }
  if (command == "CLEAR") {
    clear(out);
    return ConsoleCommand::None;
  }
  if (command == "REBOOT") {
    out.println("OK reboot requested");
    return ConsoleCommand::Reboot;
  }
  if (!command.startsWith("SET ")) {
    out.println("ERR use PROVISION HELP");
    return ConsoleCommand::None;
  }

  String assignment = command.substring(4);
  const int separator = assignment.indexOf(' ');
  if (separator <= 0) {
    out.println("ERR use PROVISION SET FIELD value");
    return ConsoleCommand::None;
  }
  String key = assignment.substring(0, separator);
  String value = assignment.substring(separator + 1);
  value.trim();
  setField(key, value, out);
  return ConsoleCommand::None;
}
