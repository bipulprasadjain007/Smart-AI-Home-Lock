#pragma once

#include <esp_camera.h>

class Camera {
 public:
  bool begin();
  bool ready() const { return initialized_; }
  bool usingPsram() const { return psram_; }

  camera_fb_t *capture();
  void release(camera_fb_t *frame);

 private:
  bool initialized_ = false;
  bool psram_ = false;
};
