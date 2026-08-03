#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace Crypto {

// The wire format is deliberately fixed: nonce (12 bytes), tag (16 bytes),
// then ciphertext. The associated data is part of the approved protocol and
// must not be changed without a protocol version change.
constexpr size_t kGcmNonceBytes = 12;
constexpr size_t kGcmTagBytes = 16;
constexpr const char *kGcmAssociatedData = "smart-ai-home-lock-v1";

bool encryptAes256Gcm(const uint8_t *plaintext, size_t plaintextLength,
                      const uint8_t aesKey[32],
                      std::vector<uint8_t> &encryptedBody,
                      std::string &error);

bool sha256(const uint8_t *data, size_t length, uint8_t digest[32]);
std::string sha256Hex(const uint8_t *data, size_t length);
std::string hmacSha256Hex(const uint8_t *key, size_t keyLength,
                          const uint8_t *data, size_t length);
inline std::string hmacSha256Hex(const uint8_t *key, size_t keyLength,
                                 const std::string &data) {
  return hmacSha256Hex(key, keyLength,
                       reinterpret_cast<const uint8_t *>(data.data()),
                       data.size());
}

void randomBytes(uint8_t *destination, size_t length);
std::string hexEncode(const uint8_t *data, size_t length);
bool parseHex(const char *text, size_t textLength, uint8_t *destination,
              size_t destinationLength);

}  // namespace Crypto
