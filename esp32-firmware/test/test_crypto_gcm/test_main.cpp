#include <Arduino.h>
#include <unity.h>

#include <cstring>

#include <mbedtls/gcm.h>

namespace {

// Test-only values. They are intentionally public and must never be reused
// for device provisioning.
constexpr uint8_t kKey[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
constexpr uint8_t kNonce[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a,
};
constexpr uint8_t kPlaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
constexpr uint8_t kExpectedCiphertext[16] = {
    0x47, 0x13, 0xf4, 0x28, 0x81, 0xb0, 0xa4, 0x6c,
    0x05, 0xd8, 0x3d, 0x30, 0x7d, 0x34, 0x96, 0x92,
};
constexpr uint8_t kExpectedTag[16] = {
    0xf6, 0x76, 0x88, 0xd4, 0x35, 0xb1, 0xc3, 0x96,
    0x4d, 0x4a, 0xd2, 0xa3, 0x41, 0x73, 0x7b, 0xe5,
};
constexpr char kAad[] = "smart-ai-home-lock-v1";

void test_fixed_aes_gcm_packet() {
  uint8_t ciphertext[sizeof(kPlaintext)] = {};
  uint8_t tag[16] = {};
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);

  TEST_ASSERT_EQUAL_INT(
      0, mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, kKey, 256));
  TEST_ASSERT_EQUAL_INT(
      0, mbedtls_gcm_starts(&context, MBEDTLS_GCM_ENCRYPT, kNonce,
                            sizeof(kNonce),
                            reinterpret_cast<const uint8_t *>(kAad),
                            strlen(kAad)));
  TEST_ASSERT_EQUAL_INT(
      0, mbedtls_gcm_update(&context, sizeof(kPlaintext), kPlaintext,
                            ciphertext));
  TEST_ASSERT_EQUAL_INT(0, mbedtls_gcm_finish(&context, tag, sizeof(tag)));
  mbedtls_gcm_free(&context);

  TEST_ASSERT_EQUAL_UINT8_ARRAY(kExpectedCiphertext, ciphertext,
                                sizeof(ciphertext));
  TEST_ASSERT_EQUAL_UINT8_ARRAY(kExpectedTag, tag, sizeof(tag));

  // The approved binary packet is nonce || tag || ciphertext, not the
  // mbedTLS/OpenSSL ciphertext || tag representation.
  uint8_t packet[sizeof(kNonce) + sizeof(tag) + sizeof(ciphertext)] = {};
  memcpy(packet, kNonce, sizeof(kNonce));
  memcpy(packet + sizeof(kNonce), tag, sizeof(tag));
  memcpy(packet + sizeof(kNonce) + sizeof(tag), ciphertext,
         sizeof(ciphertext));
  uint8_t expectedPacket[sizeof(packet)] = {};
  memcpy(expectedPacket, kNonce, sizeof(kNonce));
  memcpy(expectedPacket + sizeof(kNonce), kExpectedTag, sizeof(kExpectedTag));
  memcpy(expectedPacket + sizeof(kNonce) + sizeof(kExpectedTag),
         kExpectedCiphertext, sizeof(kExpectedCiphertext));
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expectedPacket, packet, sizeof(packet));
}

}  // namespace

void setup() {
  delay(1000);
  UNITY_BEGIN();
  RUN_TEST(test_fixed_aes_gcm_packet);
  UNITY_END();
}

void loop() {}
