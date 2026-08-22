#include "protocol.h"

#include <cstdio>
#include <cstdlib>
#include <string>

#include "crypto.h"

namespace Protocol {
namespace {

bool isSafeHeaderValue(const String &value) {
  return value.length() != 0 && value.indexOf('\r') < 0 &&
         value.indexOf('\n') < 0;
}

bool isLowerHex(const String &value, size_t length) {
  if (value.length() != length) {
    return false;
  }
  for (size_t i = 0; i < value.length(); ++i) {
    const char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool constantTimeEqual(const String &left, const std::string &right) {
  if (left.length() != right.length()) {
    return false;
  }
  uint8_t difference = 0;
  for (size_t i = 0; i < right.length(); ++i) {
    difference |= static_cast<uint8_t>(left[i]) ^
                  static_cast<uint8_t>(right[i]);
  }
  return difference == 0;
}

std::string decimal(uint64_t value) {
  char buffer[21] = {};
  snprintf(buffer, sizeof(buffer), "%llu",
           static_cast<unsigned long long>(value));
  return std::string(buffer);
}

class JsonReader {
 public:
  JsonReader(const char *data, size_t length)
      : current_(data), end_(data + length) {}

  bool parseObject(int &protocolVersion, String &status, bool &hasProtocol,
                   bool &hasStatus) {
    skipWhitespace();
    if (!consume('{')) {
      return false;
    }
    skipWhitespace();
    if (consume('}')) {
      return true;
    }

    while (current_ < end_) {
      std::string key;
      if (!parseString(key)) {
        return false;
      }
      skipWhitespace();
      if (!consume(':')) {
        return false;
      }
      skipWhitespace();

      if (key == "protocol_version") {
        if (hasProtocol || !parseInteger(protocolVersion)) {
          return false;
        }
        hasProtocol = true;
      } else if (key == "status") {
        if (hasStatus) {
          return false;
        }
        std::string decodedStatus;
        if (!parseString(decodedStatus)) {
          return false;
        }
        status = decodedStatus.c_str();
        hasStatus = true;
      } else if (!parseValue(0)) {
        return false;
      }

      skipWhitespace();
      if (consume('}')) {
        return true;
      }
      if (!consume(',')) {
        return false;
      }
      skipWhitespace();
      // A comma must be followed by another member, not by the closing brace.
      if (current_ >= end_ || *current_ == '}') {
        return false;
      }
    }
    return false;
  }

  bool atEnd() {
    skipWhitespace();
    return current_ == end_;
  }

 private:
  const char *current_;
  const char *end_;

  static bool isDigit(char value) { return value >= '0' && value <= '9'; }

  static int hexValue(char value) {
    if (value >= '0' && value <= '9') {
      return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
      return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
      return value - 'A' + 10;
    }
    return -1;
  }

  void skipWhitespace() {
    while (current_ < end_ && (*current_ == ' ' || *current_ == '\t' ||
                               *current_ == '\r' || *current_ == '\n')) {
      ++current_;
    }
  }

  bool consume(char expected) {
    if (current_ >= end_ || *current_ != expected) {
      return false;
    }
    ++current_;
    return true;
  }

  bool parseString(std::string &result) {
    result.clear();
    if (!consume('"')) {
      return false;
    }
    while (current_ < end_) {
      const unsigned char value = static_cast<unsigned char>(*current_++);
      if (value == '"') {
        return true;
      }
      if (value < 0x20) {
        return false;
      }
      if (value != '\\') {
        result.push_back(static_cast<char>(value));
        continue;
      }
      if (current_ >= end_) {
        return false;
      }
      const char escaped = *current_++;
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          result.push_back(escaped);
          break;
        case 'b':
          result.push_back('\b');
          break;
        case 'f':
          result.push_back('\f');
          break;
        case 'n':
          result.push_back('\n');
          break;
        case 'r':
          result.push_back('\r');
          break;
        case 't':
          result.push_back('\t');
          break;
        case 'u': {
          // Validate the JSON escape. Status values in the protocol are plain
          // ASCII; retaining a marker prevents an escaped value from
          // accidentally comparing equal to UNLOCK.
          if (end_ - current_ < 4 || hexValue(current_[0]) < 0 ||
              hexValue(current_[1]) < 0 || hexValue(current_[2]) < 0 ||
              hexValue(current_[3]) < 0) {
            return false;
          }
          current_ += 4;
          result.push_back('?');
          break;
        }
        default:
          return false;
      }
    }
    return false;
  }

  bool parseInteger(int &result) {
    const char *start = current_;
    if (current_ < end_ && *current_ == '-') {
      ++current_;
    }
    if (current_ >= end_ || !isDigit(*current_)) {
      return false;
    }
    if (*current_ == '0') {
      ++current_;
      if (current_ < end_ && isDigit(*current_)) {
        return false;
      }
    } else {
      while (current_ < end_ && isDigit(*current_)) {
        ++current_;
      }
    }
    if (current_ < end_ && (*current_ == '.' || *current_ == 'e' ||
                            *current_ == 'E')) {
      return false;
    }

    std::string number(start, current_);
    char *parseEnd = nullptr;
    const long parsed = strtol(number.c_str(), &parseEnd, 10);
    if (parseEnd == nullptr || *parseEnd != '\0' || parsed < 0 ||
        parsed > 2147483647L) {
      return false;
    }
    result = static_cast<int>(parsed);
    return true;
  }

  bool parseNumber() {
    if (current_ < end_ && *current_ == '-') {
      ++current_;
    }
    if (current_ >= end_ || !isDigit(*current_)) {
      return false;
    }
    if (*current_ == '0') {
      ++current_;
      if (current_ < end_ && isDigit(*current_)) {
        return false;
      }
    } else {
      while (current_ < end_ && isDigit(*current_)) {
        ++current_;
      }
    }
    if (current_ < end_ && *current_ == '.') {
      ++current_;
      if (current_ >= end_ || !isDigit(*current_)) {
        return false;
      }
      while (current_ < end_ && isDigit(*current_)) {
        ++current_;
      }
    }
    if (current_ < end_ && (*current_ == 'e' || *current_ == 'E')) {
      ++current_;
      if (current_ < end_ && (*current_ == '+' || *current_ == '-')) {
        ++current_;
      }
      if (current_ >= end_ || !isDigit(*current_)) {
        return false;
      }
      while (current_ < end_ && isDigit(*current_)) {
        ++current_;
      }
    }
    return true;
  }

  bool parseLiteral(const char *literal) {
    while (*literal != '\0') {
      if (current_ >= end_ || *current_++ != *literal++) {
        return false;
      }
    }
    return true;
  }

  bool parseArray(int depth) {
    if (depth > 8 || !consume('[')) {
      return false;
    }
    skipWhitespace();
    if (consume(']')) {
      return true;
    }
    while (true) {
      if (!parseValue(depth + 1)) {
        return false;
      }
      skipWhitespace();
      if (consume(']')) {
        return true;
      }
      if (!consume(',')) {
        return false;
      }
      skipWhitespace();
      if (current_ >= end_ || *current_ == ']') {
        return false;
      }
    }
  }

  bool parseObjectValue(int depth) {
    if (depth > 8 || !consume('{')) {
      return false;
    }
    skipWhitespace();
    if (consume('}')) {
      return true;
    }
    while (true) {
      std::string ignoredKey;
      if (!parseString(ignoredKey)) {
        return false;
      }
      skipWhitespace();
      if (!consume(':')) {
        return false;
      }
      skipWhitespace();
      if (!parseValue(depth + 1)) {
        return false;
      }
      skipWhitespace();
      if (consume('}')) {
        return true;
      }
      if (!consume(',')) {
        return false;
      }
      skipWhitespace();
      if (current_ >= end_ || *current_ == '}') {
        return false;
      }
    }
  }

  bool parseValue(int depth) {
    if (depth > 8 || current_ >= end_) {
      return false;
    }
    switch (*current_) {
      case '"': {
        std::string ignored;
        return parseString(ignored);
      }
      case '{':
        return parseObjectValue(depth);
      case '[':
        return parseArray(depth);
      case 't':
        return parseLiteral("true");
      case 'f':
        return parseLiteral("false");
      case 'n':
        return parseLiteral("null");
      default:
        return parseNumber();
    }
  }
};

bool buildSignedHeaders(const char *method, const char *path,
                        const String &deviceId, uint64_t timestamp,
                        const uint8_t hmacKey[kHmacKeyBytes],
                        const uint8_t *rawBody, size_t rawBodyLength,
                        SignedHeaders &headers, std::string &error) {
  error.clear();
  if (!isSafeHeaderValue(deviceId) || hmacKey == nullptr ||
      (rawBody == nullptr && rawBodyLength != 0)) {
    error = "invalid signing input";
    return false;
  }

  uint8_t nonce[kRequestNonceBytes] = {};
  Crypto::randomBytes(nonce, sizeof(nonce));
  const std::string nonceHex = Crypto::hexEncode(nonce, sizeof(nonce));
  const std::string bodyHash = Crypto::sha256Hex(rawBody, rawBodyLength);
  if (nonceHex.length() != kRequestNonceHexChars || bodyHash.length() != 64) {
    error = "unable to hash request body";
    return false;
  }
  const std::string canonical = canonicalRequest(
      method, path, deviceId.c_str(), timestamp, nonceHex.c_str(),
      bodyHash.c_str());
  const std::string signature = Crypto::hmacSha256Hex(
      hmacKey, kHmacKeyBytes,
      reinterpret_cast<const uint8_t *>(canonical.data()), canonical.size());
  if (signature.length() != 64) {
    error = "unable to sign request";
    return false;
  }

  headers.protocolVersion = "2";
  headers.deviceId = deviceId;
  headers.timestamp = decimal(timestamp).c_str();
  headers.requestNonce = nonceHex.c_str();
  headers.requestSignature = signature.c_str();
  return true;
}

}  // namespace

std::string canonicalRequest(const char *method, const char *path,
                             const char *deviceId, uint64_t timestamp,
                             const char *requestNonceHex,
                             const char *bodySha256Hex) {
  std::string result = "SAHL-V2\n";
  result += method;
  result += '\n';
  result += path;
  result += "\n\n";
  result += deviceId;
  result += '\n';
  result += decimal(timestamp);
  result += '\n';
  result += requestNonceHex;
  result += '\n';
  result += bodySha256Hex;
  return result;
}

bool buildUnlockHeaders(const String &deviceId, uint64_t timestamp,
                        const uint8_t hmacKey[kHmacKeyBytes],
                        const uint8_t *rawBody, size_t rawBodyLength,
                        SignedHeaders &headers, std::string &error) {
  return buildSignedHeaders("POST", kUnlockPath, deviceId, timestamp, hmacKey,
                            rawBody, rawBodyLength, headers, error);
}

bool buildHealthHeaders(const String &deviceId, uint64_t timestamp,
                        const uint8_t hmacKey[kHmacKeyBytes],
                        SignedHeaders &headers, std::string &error) {
  static const uint8_t emptyBody = 0;
  return buildSignedHeaders("GET", kHealthPath, deviceId, timestamp, hmacKey,
                            &emptyBody, 0, headers, error);
}

std::string canonicalTimeRequest(const char *deviceId,
                                 const char *requestNonceHex) {
  std::string result = "SAHL-TIME-V1\nGET\n";
  result += kDeviceTimePath;
  result += '\n';
  result += deviceId;
  result += '\n';
  result += requestNonceHex;
  return result;
}

std::string canonicalTimeResponse(const char *deviceId,
                                  const char *requestNonceHex,
                                  uint64_t serverTimestamp) {
  std::string result = "SAHL-TIME-V1\nRESPONSE\n";
  result += deviceId;
  result += '\n';
  result += requestNonceHex;
  result += '\n';
  result += decimal(serverTimestamp);
  return result;
}

bool buildTimeHeaders(const String &deviceId,
                      const uint8_t hmacKey[kHmacKeyBytes],
                      TimeHeaders &headers, std::string &error) {
  error.clear();
  if (!isSafeHeaderValue(deviceId) || hmacKey == nullptr) {
    error = "invalid time signing input";
    return false;
  }

  uint8_t nonce[kRequestNonceBytes] = {};
  Crypto::randomBytes(nonce, sizeof(nonce));
  const std::string nonceHex = Crypto::hexEncode(nonce, sizeof(nonce));
  if (nonceHex.length() != kRequestNonceHexChars) {
    error = "unable to create time challenge";
    return false;
  }
  const std::string canonical =
      canonicalTimeRequest(deviceId.c_str(), nonceHex.c_str());
  const std::string signature =
      Crypto::hmacSha256Hex(hmacKey, kHmacKeyBytes, canonical);
  if (signature.length() != 64) {
    error = "unable to sign time challenge";
    return false;
  }

  headers.protocolVersion = "1";
  headers.deviceId = deviceId;
  headers.requestNonce = nonceHex.c_str();
  headers.requestSignature = signature.c_str();
  return true;
}

bool verifyTimeResponse(const String &deviceId,
                        const TimeHeaders &requestHeaders,
                        uint64_t serverTimestamp,
                        const String &responseNonce,
                        const String &responseSignature,
                        const uint8_t hmacKey[kHmacKeyBytes],
                        std::string &error) {
  error.clear();
  if (hmacKey == nullptr || serverTimestamp < kMinimumValidUnixTime ||
      responseNonce != requestHeaders.requestNonce ||
      !isLowerHex(responseNonce, kRequestNonceHexChars) ||
      !isLowerHex(responseSignature, 64)) {
    error = "invalid authenticated-time response";
    return false;
  }
  const std::string canonical = canonicalTimeResponse(
      deviceId.c_str(), responseNonce.c_str(), serverTimestamp);
  const std::string expected =
      Crypto::hmacSha256Hex(hmacKey, kHmacKeyBytes, canonical);
  if (!constantTimeEqual(responseSignature, expected)) {
    error = "authenticated-time signature rejected";
    return false;
  }
  return true;
}

bool parseUnlockResponse(const String &json, UnlockResponse &response,
                         String &error) {
  response = UnlockResponse{};
  error = "";
  if (json.length() == 0 || json.length() > kMaxResponseBytes) {
    error = "response is empty or too large";
    return false;
  }

  int protocolVersion = -1;
  String status;
  bool hasProtocol = false;
  bool hasStatus = false;
  JsonReader reader(json.c_str(), json.length());
  if (!reader.parseObject(protocolVersion, status, hasProtocol, hasStatus) ||
      !reader.atEnd() || !hasProtocol || !hasStatus) {
    error = "response is not the required JSON object";
    return false;
  }
  response.protocolVersion = protocolVersion;
  response.status = status;
  return true;
}

}  // namespace Protocol
