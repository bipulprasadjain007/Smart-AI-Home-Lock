#pragma once

#include <Arduino.h>

#include "camera.h"

struct LivenessResult {
  bool freshSequence = false;
  uint8_t framesCaptured = 0;
  uint16_t motionSamples = 0;
  String reason;
};

class LivenessFilter {
 public:
  // This is a deliberately small capture-freshness/motion heuristic, not a
  // facial liveness detector. It captures exactly three JPEG frames and fails
  // closed unless host capture times increase and sampled frame bytes change.
  bool check(Camera &camera, LivenessResult &result);

 private:
  struct Signature {
    size_t length = 0;
    uint8_t samples[32] = {};
  };

  Signature signature(const camera_fb_t *frame) const;
  uint16_t difference(const Signature &left, const Signature &right) const;
};
