#pragma once

#include <stdint.h>

#include <string>

#include "config.h"

namespace Protocol {

struct SignedHeaders {
  String protocolVersion;
  String deviceId;
  String timestamp;
  String requestNonce;
  String requestSignature;
};

struct UnlockResponse {
  int protocolVersion = -1;
  String status;
};

struct TimeHeaders {
  String protocolVersion;
  String deviceId;
  String requestNonce;
  String requestSignature;
};

// Pure formatting helper. It is independent of HTTP so its exact newline
// layout can be checked with the host-side golden vector.
std::string canonicalRequest(const char *method, const char *path,
                             const char *deviceId, uint64_t timestamp,
                             const char *requestNonceHex,
                             const char *bodySha256Hex);

bool buildUnlockHeaders(const String &deviceId, uint64_t timestamp,
                        const uint8_t hmacKey[kHmacKeyBytes],
                        const uint8_t *rawBody, size_t rawBodyLength,
                        SignedHeaders &headers, std::string &error);

bool buildHealthHeaders(const String &deviceId, uint64_t timestamp,
                        const uint8_t hmacKey[kHmacKeyBytes],
                        SignedHeaders &headers, std::string &error);

std::string canonicalTimeRequest(const char *deviceId,
                                 const char *requestNonceHex);
std::string canonicalTimeResponse(const char *deviceId,
                                  const char *requestNonceHex,
                                  uint64_t serverTimestamp);

bool buildTimeHeaders(const String &deviceId,
                      const uint8_t hmacKey[kHmacKeyBytes],
                      TimeHeaders &headers, std::string &error);

bool verifyTimeResponse(const String &deviceId,
                        const TimeHeaders &requestHeaders,
                        uint64_t serverTimestamp,
                        const String &responseNonce,
                        const String &responseSignature,
                        const uint8_t hmacKey[kHmacKeyBytes],
                        std::string &error);

// Parses a bounded JSON object and requires both protocol_version and status
// to be present with the correct JSON types. Unknown fields are allowed, but
// duplicate required fields and malformed JSON are rejected.
bool parseUnlockResponse(const String &json, UnlockResponse &response,
                         String &error);

}  // namespace Protocol
