#include "watchdog.h"

namespace {

constexpr uint32_t kWatchdogTimeoutMs = 60000;
bool watchdogReady_ = false;

}  // namespace

bool initializeWatchdog() {
  esp_task_wdt_config_t config = {};
  config.timeout_ms = kWatchdogTimeoutMs;
  // Only explicitly subscribed tasks are watched. The current Arduino loop
  // task is subscribed below; no idle task is changed by this firmware lane.
  config.idle_core_mask = 0;
  config.trigger_panic = true;

  esp_err_t result = esp_task_wdt_init(&config);
  if (result == ESP_ERR_INVALID_STATE) {
    // Arduino may have initialized the TWDT before setup(). Reconfigure it to
    // the bounded firmware timeout rather than calling the legacy API.
    result = esp_task_wdt_reconfigure(&config);
  }
  if (result != ESP_OK) {
    watchdogReady_ = false;
    return false;
  }

  // NULL means the task executing setup()/loop(), not an arbitrary task.
  result = esp_task_wdt_add(nullptr);
  if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) {
    watchdogReady_ = false;
    return false;
  }
  if (esp_task_wdt_status(nullptr) != ESP_OK) {
    watchdogReady_ = false;
    return false;
  }
  watchdogReady_ = true;
  return true;
}

bool watchdogReady() { return watchdogReady_; }
