#include "camera.h"

#include <Arduino.h>

namespace {

// Official AI Thinker ESP32-CAM pin map. GPIO13 is reserved for the relay in
// this project; do not enable the micro-SD interface at the same time.
constexpr int8_t PWDN_GPIO_NUM = 32;
constexpr int8_t RESET_GPIO_NUM = -1;
constexpr int8_t XCLK_GPIO_NUM = 0;
constexpr int8_t SIOD_GPIO_NUM = 26;
constexpr int8_t SIOC_GPIO_NUM = 27;
constexpr int8_t Y9_GPIO_NUM = 35;
constexpr int8_t Y8_GPIO_NUM = 34;
constexpr int8_t Y7_GPIO_NUM = 39;
constexpr int8_t Y6_GPIO_NUM = 36;
constexpr int8_t Y5_GPIO_NUM = 21;
constexpr int8_t Y4_GPIO_NUM = 19;
constexpr int8_t Y3_GPIO_NUM = 18;
constexpr int8_t Y2_GPIO_NUM = 5;
constexpr int8_t VSYNC_GPIO_NUM = 25;
constexpr int8_t HREF_GPIO_NUM = 23;
constexpr int8_t PCLK_GPIO_NUM = 22;

}  // namespace

bool Camera::begin() {
  if (initialized_) {
    return true;
  }

  psram_ = psramFound();
  camera_config_t config = {};
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer = LEDC_TIMER_0;
  config.pin_d0 = Y2_GPIO_NUM;
  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;
  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;
  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;
  config.pin_d7 = Y9_GPIO_NUM;
  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;
  config.pin_sccb_sda = SIOD_GPIO_NUM;
  config.pin_sccb_scl = SIOC_GPIO_NUM;
  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;
  config.frame_size = psram_ ? FRAMESIZE_VGA : FRAMESIZE_QVGA;
  config.jpeg_quality = psram_ ? 10 : 13;
  config.fb_count = psram_ ? 2 : 1;
  config.grab_mode = psram_ ? CAMERA_GRAB_LATEST : CAMERA_GRAB_WHEN_EMPTY;
  config.fb_location = psram_ ? CAMERA_FB_IN_PSRAM : CAMERA_FB_IN_DRAM;

  if (esp_camera_init(&config) != ESP_OK) {
    initialized_ = false;
    return false;
  }

  initialized_ = true;
  return true;
}

camera_fb_t *Camera::capture() {
  if (!initialized_) {
    return nullptr;
  }
  camera_fb_t *frame = esp_camera_fb_get();
  if (frame == nullptr || frame->format != PIXFORMAT_JPEG || frame->len == 0) {
    if (frame != nullptr) {
      esp_camera_fb_return(frame);
    }
    return nullptr;
  }
  return frame;
}

void Camera::release(camera_fb_t *frame) {
  if (frame != nullptr) {
    esp_camera_fb_return(frame);
  }
}
