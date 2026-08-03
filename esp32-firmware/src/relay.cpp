#include "relay.h"

#include <Arduino.h>

void Relay::begin(uint8_t pin, bool activeHigh) {
  pin_ = pin;
  activeHigh_ = activeHigh;
  // GPIO13 is the documented fallback. A bad provisioned pin is never
  // allowed to become an energized output.
  if (!(pin_ == 4 || pin_ == 13 || pin_ == 14)) {
    pin_ = 13;
    activeHigh_ = true;
  }
  // Set the output latch to the inactive level before enabling the output to
  // minimize a reset-time pulse. The external relay driver should also have
  // a pull-down/pull-up matching this inactive level for brownout safety.
  digitalWrite(pin_, activeHigh_ ? LOW : HIGH);
  pinMode(pin_, OUTPUT);
  initialized_ = true;
  off();
}

void Relay::off() {
  energized_ = false;
  if (initialized_) {
    digitalWrite(pin_, activeHigh_ ? LOW : HIGH);
  }
}

void Relay::on() {
  if (!initialized_) {
    return;
  }
  energized_ = true;
  digitalWrite(pin_, activeHigh_ ? HIGH : LOW);
}
