#include "liveness.h"

#include <esp_timer.h>

#include "watchdog.h"

LivenessFilter::Signature LivenessFilter::signature(
    const camera_fb_t *frame) const {
  Signature result;
  if (frame == nullptr || frame->buf == nullptr || frame->len == 0) {
    return result;
  }
  result.length = frame->len;
  for (size_t i = 0; i < sizeof(result.samples); ++i) {
    const size_t index = (i * (frame->len - 1)) / (sizeof(result.samples) - 1);
    result.samples[i] = frame->buf[index];
  }
  return result;
}

uint16_t LivenessFilter::difference(const Signature &left,
                                    const Signature &right) const {
  uint16_t changed = left.length == right.length ? 0 : 1;
  for (size_t i = 0; i < sizeof(left.samples); ++i) {
    if (left.samples[i] != right.samples[i]) {
      ++changed;
    }
  }
  return changed;
}

bool LivenessFilter::check(Camera &camera, LivenessResult &result) {
  result = LivenessResult{};
  Signature signatures[3];
  int64_t previousCaptureEnd = -1;

  for (size_t i = 0; i < 3; ++i) {
    const int64_t captureStart = esp_timer_get_time();
    camera_fb_t *frame = camera.capture();
    const int64_t captureEnd = esp_timer_get_time();
    if (frame == nullptr || captureEnd <= captureStart ||
        (previousCaptureEnd >= 0 && captureEnd <= previousCaptureEnd)) {
      if (frame != nullptr) {
        camera.release(frame);
      }
      result.reason = "could not establish increasing fresh-frame captures";
      return false;
    }
    signatures[i] = signature(frame);
    camera.release(frame);
    ++result.framesCaptured;
    previousCaptureEnd = captureEnd;

    if (i != 2) {
      // Give the camera a real interval in which a new frame can arrive.
      delay(30);
      feedWatchdog();
    }
  }

  const uint16_t change01 = difference(signatures[0], signatures[1]);
  const uint16_t change12 = difference(signatures[1], signatures[2]);
  result.motionSamples = change01 + change12;
  if (change01 == 0 && change12 == 0) {
    result.reason = "three captures were byte-identical; freshness unknown";
    return false;
  }

  result.freshSequence = true;
  result.reason = "fresh three-frame heuristic passed";
  return true;
}
