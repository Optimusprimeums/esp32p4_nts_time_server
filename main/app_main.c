#include "app_state.h"
#include "clock_discipline.h"
#include "device_config.h"
#include "diagnostics.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "ntp_server.h"
#include "pps_service.h"
#include "web_console.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

#include "nvs_flash.h"

static const char *TAG = "MAIN";

static void enter_fail_closed(const char *component, esp_err_t err)
{
    ESP_LOGE(TAG,
             "%s initialization failed: %s (0x%x)",
             component,
             esp_err_to_name(err),
             (unsigned int)err);

    app_state_set_clock_solution(APP_CLOCK_FAIL_CLOSED,
                                 false,
                                 0,
                                 0.0,
                                 0,
                                 0,
                                 0,
                                 0);
}

void app_main(void)
{
    ESP_LOGI(TAG, "Starting GNSS-disciplined NTP server");

    esp_err_t err = nvs_flash_init();

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "NVS initialization failed: %s",
                 esp_err_to_name(err));
        return;
    }

    err = esp_netif_init();

    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG,
                 "esp_netif initialization failed: %s",
                 esp_err_to_name(err));
        return;
    }

    err = esp_event_loop_create_default();

    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG,
                 "event-loop initialization failed: %s",
                 esp_err_to_name(err));
        return;
    }

    app_state_init();

    err = device_config_init();

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Device configuration initialization failed: %s",
                 esp_err_to_name(err));
        return;
    }

    err = pps_service_init();

    if (err != ESP_OK) {
        enter_fail_closed("PPS service", err);
        return;
    }

    err = gnss_service_init();

    if (err != ESP_OK) {
        enter_fail_closed("GNSS service", err);
        return;
    }

    err = clock_discipline_init();

    if (err != ESP_OK) {
        enter_fail_closed("clock discipline", err);
        return;
    }

    err = diagnostics_start();

    if (err != ESP_OK) {
        enter_fail_closed("diagnostics", err);
        return;
    }

    err = eth_service_init();

    if (err != ESP_OK) {
        enter_fail_closed("Ethernet initialization", err);
        return;
    }

    err = eth_service_start();

    if (err != ESP_OK) {
        enter_fail_closed("Ethernet startup", err);
        return;
    }

    eth_service_wait_for_ip();

    err = ntp_server_start();

    if (err != ESP_OK) {
        enter_fail_closed("NTP server startup", err);
        return;
    }

    err = web_console_start();

    if (err != ESP_OK) {
        /*
         * The read-only console is not part of the timing or NTP trust path.
         * Keep NTP operational if the optional management console fails.
         */
        ESP_LOGW(TAG,
                 "Web console did not start: %s",
                 esp_err_to_name(err));
    }

    ESP_LOGI(TAG,
             "Ethernet, NTP, and read-only HTTPS management console started");
}
