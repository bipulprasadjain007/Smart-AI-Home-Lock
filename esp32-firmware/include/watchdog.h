#pragma once

#include <Arduino.h>
#include <esp_task_wdt.h>

// Arduino-ESP32 3.x uses the ESP-IDF 5.x configuration-based task watchdog
// API. setup() must initialize and subscribe the current loop task before any
// network or camera work is allowed to proceed.
bool initializeWatchdog();
bool watchdogReady();

inline void feedWatchdog() {
  if (watchdogReady()) {
    (void)esp_task_wdt_reset();
  }
  // Feeding is safe before setup completes and after a failed initialization;
  // yielding still lets the fail-closed loop remain responsive.
  yield();
}
