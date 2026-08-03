#pragma once

#include <Arduino.h>

#include <vector>

#include "config.h"
#include "protocol.h"

enum class RequestState {
  NotSent,
  Completed,
  Uncertain,
};

struct UnlockTransportResult {
  RequestState state = RequestState::NotSent;
  bool tlsSucceeded = false;
  int httpStatus = 0;
  bool jsonParsed = false;
  Protocol::UnlockResponse response;
  String error;
};

struct HealthTransportResult {
  RequestState state = RequestState::NotSent;
  bool tlsSucceeded = false;
  int httpStatus = 0;
  String responseBody;
  String error;
};

class Transport {
 public:
  bool ensureWifi(const DeviceConfig &config,
                  uint32_t timeoutMs = kWifiWaitMs);

  // This function sends one unlock packet at most. A negative HTTP result is
  // marked Uncertain because the packet may have reached the server; callers
  // must not retry it automatically.
  UnlockTransportResult postUnlock(
      const DeviceConfig &config, const std::vector<uint8_t> &body,
      const Protocol::SignedHeaders &headers);

  HealthTransportResult getHealth(const DeviceConfig &config,
                                  const Protocol::SignedHeaders &headers);

 private:
  String urlFor(const DeviceConfig &config, const char *path) const;
  void configureTls(class NetworkClientSecure &client,
                    const DeviceConfig &config) const;
};
