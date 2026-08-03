#include "crypto.h"

#include <Arduino.h>
#include <esp_system.h>

#include <cstring>

#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

namespace Crypto {
namespace {

constexpr size_t kMaxPlaintextBytes = 200U * 1024U;
constexpr char kHexDigits[] = "0123456789abcdef";

void setError(std::string &error, const char *message) { error = message; }

int hexValue(char value) {
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

bool runSha256(const uint8_t *data, size_t length, uint8_t digest[32]) {
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  const mbedtls_md_info_t *info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  bool ok = info != nullptr && mbedtls_md_setup(&context, info, 0) == 0;
  if (ok) {
    ok = mbedtls_md_starts(&context) == 0;
  }
  if (ok && length != 0) {
    ok = mbedtls_md_update(&context, data, length) == 0;
  }
  if (ok) {
    ok = mbedtls_md_finish(&context, digest) == 0;
  }
  mbedtls_md_free(&context);
  return ok;
}

}  // namespace

bool encryptAes256Gcm(const uint8_t *plaintext, size_t plaintextLength,
                      const uint8_t aesKey[32],
                      std::vector<uint8_t> &encryptedBody,
                      std::string &error) {
  encryptedBody.clear();
  error.clear();
  if ((plaintext == nullptr && plaintextLength != 0) || aesKey == nullptr) {
    setError(error, "invalid AES input");
    return false;
  }
  if (plaintextLength > kMaxPlaintextBytes) {
    setError(error, "JPEG is larger than the configured limit");
    return false;
  }

  constexpr size_t envelopeBytes = kGcmNonceBytes + kGcmTagBytes;
  std::vector<uint8_t> result(envelopeBytes + plaintextLength);
  randomBytes(result.data(), kGcmNonceBytes);

  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);
  bool ok =
      mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, aesKey, 256) == 0;
  if (ok) {
    ok = mbedtls_gcm_starts(
             &context, MBEDTLS_GCM_ENCRYPT, result.data(), kGcmNonceBytes,
             reinterpret_cast<const uint8_t *>(kGcmAssociatedData),
             strlen(kGcmAssociatedData)) == 0;
  }
  if (ok && plaintextLength != 0) {
    ok = mbedtls_gcm_update(&context, plaintextLength, plaintext,
                            result.data() + envelopeBytes) == 0;
  }

  uint8_t tag[kGcmTagBytes] = {};
  if (ok) {
    ok = mbedtls_gcm_finish(&context, tag, kGcmTagBytes) == 0;
  }
  mbedtls_gcm_free(&context);

  if (!ok) {
    setError(error, "AES-GCM operation failed");
    return false;
  }

  // The server's established body layout is nonce || tag || ciphertext.
  memcpy(result.data() + kGcmNonceBytes, tag, kGcmTagBytes);
  encryptedBody.swap(result);
  return true;
}

bool sha256(const uint8_t *data, size_t length, uint8_t digest[32]) {
  if ((data == nullptr && length != 0) || digest == nullptr) {
    return false;
  }
  return runSha256(data, length, digest);
}

std::string sha256Hex(const uint8_t *data, size_t length) {
  uint8_t digest[32] = {};
  if (!sha256(data, length, digest)) {
    return {};
  }
  return hexEncode(digest, sizeof(digest));
}

std::string hmacSha256Hex(const uint8_t *key, size_t keyLength,
                          const uint8_t *data, size_t length) {
  if ((key == nullptr && keyLength != 0) ||
      (data == nullptr && length != 0)) {
    return {};
  }

  uint8_t digest[32] = {};
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  const mbedtls_md_info_t *info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  bool ok = info != nullptr && mbedtls_md_setup(&context, info, 1) == 0;
  if (ok) {
    ok = mbedtls_md_hmac_starts(&context, key, keyLength) == 0;
  }
  if (ok && length != 0) {
    ok = mbedtls_md_hmac_update(&context, data, length) == 0;
  }
  if (ok) {
    ok = mbedtls_md_hmac_finish(&context, digest) == 0;
  }
  mbedtls_md_free(&context);
  return ok ? hexEncode(digest, sizeof(digest)) : std::string();
}

void randomBytes(uint8_t *destination, size_t length) {
  if (destination == nullptr) {
    return;
  }
  size_t offset = 0;
  while (offset < length) {
    const uint32_t randomWord = esp_random();
    const size_t remaining = length - offset;
    const size_t copyLength = remaining < sizeof(randomWord)
                                  ? remaining
                                  : sizeof(randomWord);
    memcpy(destination + offset, &randomWord, copyLength);
    offset += copyLength;
  }
}

std::string hexEncode(const uint8_t *data, size_t length) {
  if (data == nullptr && length != 0) {
    return {};
  }
  std::string result;
  result.resize(length * 2);
  for (size_t i = 0; i < length; ++i) {
    result[i * 2] = kHexDigits[data[i] >> 4];
    result[i * 2 + 1] = kHexDigits[data[i] & 0x0F];
  }
  return result;
}

bool parseHex(const char *text, size_t textLength, uint8_t *destination,
              size_t destinationLength) {
  if (text == nullptr || destination == nullptr ||
      textLength != destinationLength * 2) {
    return false;
  }
  for (size_t i = 0; i < destinationLength; ++i) {
    const int high = hexValue(text[i * 2]);
    const int low = hexValue(text[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    destination[i] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

}  // namespace Crypto
