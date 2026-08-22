#include "transport.h"

#include <HTTPClient.h>
#include <NetworkClientSecure.h>
#include <WiFi.h>

#include "watchdog.h"

namespace {

uint32_t elapsedSince(uint32_t start) { return millis() - start; }

class BoundedResponseStream : public Stream {
 public:
  explicit BoundedResponseStream(size_t maximum) : maximum_(maximum) {}

  size_t write(const uint8_t *buffer, size_t size) override {
    if (overflow_ || buffer == nullptr || size > maximum_ - body_.length()) {
      overflow_ = true;
      return 0;
    }
    body_.concat(reinterpret_cast<const char *>(buffer),
                 static_cast<unsigned int>(size));
    return size;
  }

  size_t write(uint8_t value) override { return write(&value, 1); }
  int available() override { return 0; }
  int read() override { return -1; }
  int peek() override { return -1; }
  void flush() override {}

  bool overflowed() const { return overflow_; }
  const String &body() const { return body_; }

 private:
  String body_;
  size_t maximum_;
  bool overflow_ = false;
};

void addSignedHeaders(HTTPClient &http,
                      const Protocol::SignedHeaders &headers) {
  http.addHeader("X-Protocol-Version", headers.protocolVersion);
  http.addHeader("X-Device-ID", headers.deviceId);
  http.addHeader("X-Timestamp", headers.timestamp);
  http.addHeader("X-Request-Nonce", headers.requestNonce);
  http.addHeader("X-Request-Signature", headers.requestSignature);
}

void addTimeHeaders(HTTPClient &http,
                    const Protocol::TimeHeaders &headers) {
  http.addHeader("X-Time-Protocol-Version", headers.protocolVersion);
  http.addHeader("X-Device-ID", headers.deviceId);
  http.addHeader("X-Time-Nonce", headers.requestNonce);
  http.addHeader("X-Time-Signature", headers.requestSignature);
}

bool parseUnixTimestamp(const String &value, uint64_t &timestamp) {
  if (value.length() == 0 || value.length() > 20) {
    return false;
  }
  uint64_t parsed = 0;
  for (size_t i = 0; i < value.length(); ++i) {
    const char c = value[i];
    if (c < '0' || c > '9') {
      return false;
    }
    const uint8_t digit = static_cast<uint8_t>(c - '0');
    if (parsed > (UINT64_MAX - digit) / 10) {
      return false;
    }
    parsed = parsed * 10 + digit;
  }
  timestamp = parsed;
  return true;
}

bool readBoundedResponse(HTTPClient &http, String &body, String &error) {
  const int contentLength = http.getSize();
  if (contentLength > static_cast<int>(kMaxResponseBytes)) {
    error = "response exceeds bounded size";
    return false;
  }

  // HTTPClient performs its normal body/chunk handling while writing to this
  // bounded Stream. This keeps chunked or missing Content-Length responses
  // from allocating unbounded memory before JSON parsing.
  BoundedResponseStream bounded(kMaxResponseBytes);
  const int written = http.writeToStream(&bounded);
  if (written < 0 || bounded.overflowed() ||
      (contentLength >= 0 && written != contentLength)) {
    error = "response exceeds bounded size";
    return false;
  }
  body = bounded.body();
  return true;
}

}  // namespace

String Transport::urlFor(const DeviceConfig &config, const char *path) const {
  String url = "https://";
  url += config.endpointHost;
  if (config.endpointPort != 443) {
    url += ":";
    url += config.endpointPort;
  }
  url += path;
  return url;
}

void Transport::configureTls(NetworkClientSecure &client,
                             const DeviceConfig &config) const {
  // A missing CA is rejected by DeviceConfig::valid(). There is intentionally
  // no insecure/fallback TLS mode in this firmware.
  client.setCACert(config.caCertificate.c_str());
  client.setHandshakeTimeout(kTlsTimeoutMs / 1000);
  // NetworkClientSecure expresses its socket timeout in seconds; HTTPClient
  // below uses milliseconds.
  client.setTimeout(kTlsTimeoutMs / 1000);
}

bool Transport::ensureWifi(const DeviceConfig &config, uint32_t timeoutMs) {
  if (!config.valid()) {
    return false;
  }
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  const uint32_t start = millis();
  const uint32_t backoffMs[] = {250, 500, 1000};

  for (size_t attempt = 0; attempt < 3; ++attempt) {
    if (elapsedSince(start) >= timeoutMs) {
      return false;
    }
    WiFi.disconnect(false);
    delay(25);
    WiFi.begin(config.wifiSsid.c_str(), config.wifiPassword.c_str());

    while (WiFi.status() != WL_CONNECTED && elapsedSince(start) < timeoutMs) {
      delay(100);
      feedWatchdog();
    }
    if (WiFi.status() == WL_CONNECTED) {
      return true;
    }
    const uint32_t elapsed = elapsedSince(start);
    if (elapsed >= timeoutMs) {
      return false;
    }
    const uint32_t remaining = timeoutMs - elapsed;
    const uint32_t wait = backoffMs[attempt] < remaining
                              ? backoffMs[attempt]
                              : remaining;
    delay(wait);
    feedWatchdog();
  }
  return WiFi.status() == WL_CONNECTED;
}

UnlockTransportResult Transport::postUnlock(
    const DeviceConfig &config, const std::vector<uint8_t> &body,
    const Protocol::SignedHeaders &headers) {
  UnlockTransportResult result;
  if (!config.valid()) {
    result.error = "invalid device configuration";
    return result;
  }
  if (!ensureWifi(config)) {
    result.error = "Wi-Fi unavailable before unlock request";
    return result;
  }
  if (body.empty() || body.size() > kMaxUnlockJpegBytes + 28) {
    result.error = "unlock body is outside the configured bounds";
    return result;
  }

  NetworkClientSecure tlsClient;
  configureTls(tlsClient, config);
  HTTPClient http;
  http.setConnectTimeout(kTlsTimeoutMs);
  http.setTimeout(kHttpTimeoutMs);
  const String url = urlFor(config, kUnlockPath);
  if (!http.begin(tlsClient, url)) {
    result.error = "HTTP client setup failed";
    return result;
  }
  http.addHeader("Content-Type", "application/octet-stream");
  addSignedHeaders(http, headers);

  // Exactly one send is intentional. If POST returns a negative value, the
  // transport cannot know whether the server received the packet, so this is
  // marked Uncertain and is never retried by this firmware.
  uint8_t *rawBody = const_cast<uint8_t *>(body.data());
  feedWatchdog();
  const int status = http.POST(rawBody, body.size());
  feedWatchdog();
  result.httpStatus = status;
  if (status < 0) {
    result.state = RequestState::Uncertain;
    result.error = http.errorToString(status);
    http.end();
    return result;
  }

  result.state = RequestState::Completed;
  result.tlsSucceeded = true;  // An HTTP status means TLS completed.
  if (status != 200) {
    result.error = "unlock endpoint rejected the HTTP request";
    http.end();
    return result;
  }

  String responseBody;
  if (!readBoundedResponse(http, responseBody, result.error)) {
    http.end();
    return result;
  }
  String parseError;
  result.jsonParsed =
      Protocol::parseUnlockResponse(responseBody, result.response, parseError);
  if (!result.jsonParsed) {
    result.error = parseError;
  }
  http.end();
  return result;
}

HealthTransportResult Transport::getHealth(
    const DeviceConfig &config, const Protocol::SignedHeaders &headers) {
  HealthTransportResult result;
  if (!config.valid()) {
    result.error = "invalid device configuration";
    return result;
  }
  if (!ensureWifi(config)) {
    result.error = "Wi-Fi unavailable before health request";
    return result;
  }

  NetworkClientSecure tlsClient;
  configureTls(tlsClient, config);
  HTTPClient http;
  http.setConnectTimeout(kTlsTimeoutMs);
  http.setTimeout(kHttpTimeoutMs);
  if (!http.begin(tlsClient, urlFor(config, kHealthPath))) {
    result.error = "HTTP client setup failed";
    return result;
  }
  // The deployed /api/health route is public and ignores these extra v2
  // headers. Keeping them does not gate health or actuate the relay.
  addSignedHeaders(http, headers);

  // Health is also one request per console command. It has no retry loop.
  feedWatchdog();
  const int status = http.GET();
  feedWatchdog();
  result.httpStatus = status;
  if (status < 0) {
    result.state = RequestState::Uncertain;
    result.error = http.errorToString(status);
    http.end();
    return result;
  }
  result.state = RequestState::Completed;
  result.tlsSucceeded = true;
  if (status == 200) {
    readBoundedResponse(http, result.responseBody, result.error);
  } else {
    result.error = "health endpoint returned a non-200 status";
  }
  http.end();
  return result;
}

TimeTransportResult Transport::getAuthenticatedTime(
    const DeviceConfig &config, const Protocol::TimeHeaders &headers) {
  TimeTransportResult result;
  if (!config.valid()) {
    result.error = "invalid device configuration";
    return result;
  }
  if (!ensureWifi(config)) {
    result.error = "Wi-Fi unavailable before authenticated-time request";
    return result;
  }

  NetworkClientSecure tlsClient;
  configureTls(tlsClient, config);
  HTTPClient http;
  http.setConnectTimeout(kTlsTimeoutMs);
  http.setTimeout(kHttpTimeoutMs);
  if (!http.begin(tlsClient, urlFor(config, kDeviceTimePath))) {
    result.error = "authenticated-time HTTP setup failed";
    return result;
  }

  static const char *responseHeaders[] = {
      "X-Time-Protocol-Version", "X-Device-ID", "X-Time-Nonce",
      "X-Server-Time", "X-Time-Signature"};
  http.collectHeaders(responseHeaders,
                      sizeof(responseHeaders) / sizeof(responseHeaders[0]));
  addTimeHeaders(http, headers);

  feedWatchdog();
  const int status = http.GET();
  feedWatchdog();
  result.httpStatus = status;
  if (status < 0) {
    result.state = RequestState::Uncertain;
    result.error = http.errorToString(status);
    http.end();
    return result;
  }
  result.state = RequestState::Completed;
  result.tlsSucceeded = true;
  if (status != 200 || http.header("X-Time-Protocol-Version") != "1" ||
      http.header("X-Device-ID") != config.deviceId) {
    result.error = "authenticated-time endpoint rejected the request";
    http.end();
    return result;
  }

  const String timestampHeader = http.header("X-Server-Time");
  uint64_t serverTime = 0;
  if (!parseUnixTimestamp(timestampHeader, serverTime)) {
    result.error = "authenticated-time timestamp is invalid";
    http.end();
    return result;
  }

  std::string protocolError;
  result.authenticated = Protocol::verifyTimeResponse(
      config.deviceId, headers, serverTime, http.header("X-Time-Nonce"),
      http.header("X-Time-Signature"), config.hmacKey, protocolError);
  if (!result.authenticated) {
    result.error = protocolError.c_str();
    http.end();
    return result;
  }
  result.serverTime = serverTime;
  http.end();
  return result;
}
