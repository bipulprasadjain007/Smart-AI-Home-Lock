#pragma once

#include <Arduino.h>
#include <stddef.h>
#include <time.h>
#include <stdint.h>

#ifndef SAHL_PRODUCTION
#define SAHL_PRODUCTION 0
#endif

#ifndef SAHL_REQUIRE_FLASH_ENCRYPTION
#define SAHL_REQUIRE_FLASH_ENCRYPTION 1
#endif

// This lane currently uses ordinary unauthenticated SNTP only. A production
// build is intentionally blocked until an authenticated/multi-source time
// implementation is added; setting SAHL_PRODUCTION cannot silently weaken the
// time trust gate.
#if SAHL_PRODUCTION
#if !SAHL_REQUIRE_FLASH_ENCRYPTION
#error "SAHL_PRODUCTION requires SAHL_REQUIRE_FLASH_ENCRYPTION=1"
#endif
#error "SAHL_PRODUCTION is blocked until authenticated time trust is implemented"
#endif

constexpr size_t kAesKeyBytes = 32;
constexpr size_t kHmacKeyBytes = 32;
constexpr size_t kRequestNonceBytes = 16;
constexpr size_t kRequestNonceHexChars = kRequestNonceBytes * 2;
constexpr size_t kMaxUnlockJpegBytes = 200U * 1024U;
constexpr size_t kMaxResponseBytes = 4096;
constexpr size_t kMaxProvisioningLine = 4096;

constexpr uint16_t kDefaultEndpointPort = 443;
constexpr uint8_t kDefaultRelayPin = 13;
constexpr bool kDefaultRelayActiveHigh = true;
constexpr uint32_t kDefaultRelayPulseMs = 750;
constexpr uint32_t kWifiWaitMs = 12000;
constexpr uint32_t kNtpWaitMs = 15000;
constexpr uint32_t kTlsTimeoutMs = 15000;
constexpr uint32_t kHttpTimeoutMs = 15000;
constexpr time_t kMinimumValidUnixTime = 1700000000;

constexpr const char *kUnlockPath = "/api/unlock";
constexpr const char *kHealthPath = "/api/health";
constexpr const char *kDefaultNtpServer = "pool.ntp.org";

struct DeviceConfig {
  String deviceId;
  String wifiSsid;
  String wifiPassword;
  String endpointHost;
  uint16_t endpointPort = kDefaultEndpointPort;
  String caCertificate;
  String ntpServer = kDefaultNtpServer;
  uint8_t aesKey[kAesKeyBytes] = {};
  uint8_t hmacKey[kHmacKeyBytes] = {};
  bool aesKeyConfigured = false;
  bool hmacKeyConfigured = false;
  uint8_t relayPin = kDefaultRelayPin;
  bool relayActiveHigh = kDefaultRelayActiveHigh;
  uint32_t relayPulseMs = kDefaultRelayPulseMs;

  bool valid(String *reason = nullptr) const;
};

// NVS is sufficient for development configuration only. Production builds
// must pass the flash-encryption gate (or a future secure-element integration).
bool secureStorageReady();

enum class ConsoleCommand {
  None,
  Unlock,
  Health,
  Reboot,
};

class ConfigStore {
 public:
  bool load();
  bool save(Stream &out);
  bool clear(Stream &out);

  const DeviceConfig &config() const { return config_; }

  // The line is handled without ever printing passwords, keys, or certificate
  // contents. Provisioning is performed over a physically connected serial
  // console and is persisted only after an explicit SAVE.
  ConsoleCommand handleSerialLine(const String &line, Stream &out);
  void printStatus(Stream &out) const;
  void printHelp(Stream &out) const;

 private:
  DeviceConfig config_;

  bool setField(const String &key, String value, Stream &out);
  bool parsePort(const String &value, uint16_t &port) const;
  bool parseBool(const String &value, bool &result) const;
  bool parseUint32(const String &value, uint32_t &result) const;
};
