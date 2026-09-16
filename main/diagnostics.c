#include "diagnostics.h"

#include <inttypes.h>

#include "app_config.h"
#include "app_state.h"
#include "clock_discipline.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "ntp_server.h"
#include "pps_service.h"

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "DIAG";

static const char *clock_state_to_string(app_clock_state_t state)
{
    switch (state) {
    case APP_CLOCK_UNSYNCHRONIZED:
        return "UNSYNCHRONIZED";

    case APP_CLOCK_ACQUIRING:
        return "ACQUIRING";

    case APP_CLOCK_SYNCHRONIZED:
        return "SYNCHRONIZED";

    case APP_CLOCK_HOLDOVER:
        return "HOLDOVER";

    case APP_CLOCK_FAIL_CLOSED:
        return "FAIL_CLOSED";

    default:
        return "UNKNOWN";
    }
}

static const char *leap_to_string(app_leap_indicator_t leap)
{
    switch (leap) {
    case APP_LEAP_NO_WARNING:
        return "NONE";

    case APP_LEAP_ADD_SECOND:
        return "ADD";

    case APP_LEAP_DELETE_SECOND:
        return "DELETE";

    case APP_LEAP_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static void diagnostics_task(void *arg)
{
    (void)arg;

    while (true) {
        pps_service_status_t pps_status;
        gnss_service_status_t gnss_status;
        clock_discipline_status_t clock_status;
        eth_service_status_t eth_status;
        ntp_server_status_t ntp_status;

        (void)pps_service_get_status(&pps_status);
        (void)gnss_service_get_status(&gnss_status);
        (void)clock_discipline_get_status(&clock_status);
        (void)eth_service_get_status(&eth_status);
        (void)ntp_server_get_status(&ntp_status);

        ESP_LOGI(
            TAG,
            "clock=%s solution=%d samples=%" PRIu32 "/%" PRIu32
            " phase=%" PRId64 " ns freq=%.6f ppm holdover=%" PRIu32 " s",
            clock_state_to_string(clock_status.state),
            clock_status.solution_valid,
            clock_status.accepted_samples,
            clock_status.rejected_samples,
            clock_status.phase_error_ns,
            clock_status.frequency_ppm,
            clock_status.holdover_seconds);

        ESP_LOGI(
            TAG,
            "pps: ETM=%d valid=%d edges=%" PRIu32
            " age=%" PRId64 " us period=%" PRIu32
            " us jitter=%" PRIu32 " us drops=%" PRIu32,
            pps_status.etm_active,
            pps_status.interval_valid,
            pps_status.edge_count,
            pps_status.age_us,
            pps_status.period_us,
            pps_status.jitter_us,
            pps_status.queue_drops);

        ESP_LOGI(
            TAG,
            "gnss: utc_valid=%d ubx_pvt=%d utc=%" PRId64
            " fix=%d type=%u sv=%u resolved=%d leap=%s",
            gnss_status.utc_valid,
            gnss_status.utc_from_ubx_pvt,
            gnss_status.utc_seconds,
            gnss_status.gnss_fix_valid,
            gnss_status.fix_type,
            gnss_status.satellites_used,
            gnss_status.gnss_time_fully_resolved,
            leap_to_string(gnss_status.leap_indicator));

        ESP_LOGI(
            TAG,
            "eth: started=%d link=%d ipv4=%d mac=%02x:%02x:%02x:%02x:%02x:%02x",
            eth_status.started,
            eth_status.link_up,
            eth_status.ipv4_ready,
            eth_status.mac[0],
            eth_status.mac[1],
            eth_status.mac[2],
            eth_status.mac[3],
            eth_status.mac[4],
            eth_status.mac[5]);

        ESP_LOGI(
            TAG,
            "ntp: started=%d bound=%d req=%" PRIu32
            " valid_rsp=%" PRIu32 " invalid=%" PRIu32
            " unsync_drop=%" PRIu32 " rate_kod=%" PRIu32
            " send_fail=%" PRIu32 " socket_fail=%" PRIu32
            " stratum=%u li=%u dispersion=0x%08" PRIx32,
            ntp_status.started,
            ntp_status.socket_bound,
            ntp_status.requests_received,
            ntp_status.normal_responses,
            ntp_status.invalid_requests,
            ntp_status.unsynchronized_drops,
            ntp_status.rate_kod_responses,
            ntp_status.send_failures,
            ntp_status.socket_open_failures,
            ntp_status.advertised_stratum,
            ntp_status.advertised_leap_indicator,
            ntp_status.advertised_root_dispersion);

        vTaskDelay(pdMS_TO_TICKS(5000U));
    }
}

esp_err_t diagnostics_start(void)
{
    const BaseType_t task_created = xTaskCreate(
        diagnostics_task,
        "diagnostics",
        APP_DIAGNOSTICS_TASK_STACK_SIZE,
        NULL,
        APP_DIAGNOSTICS_TASK_PRIORITY,
        NULL);

    return task_created == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}