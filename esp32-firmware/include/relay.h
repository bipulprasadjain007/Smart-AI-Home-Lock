#pragma once

#include <stdint.h>

class Relay {
 public:
  void begin(uint8_t pin, bool activeHigh);
  void off();
  void on();
  bool isOn() const { return energized_; }

 private:
  uint8_t pin_ = 13;
  bool activeHigh_ = true;
  bool initialized_ = false;
  bool energized_ = false;
};
