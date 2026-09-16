#include "clock_discipline.h"

#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app_config.h"
#include "app_state.h"
#include "gnss_service.h"
#include "pps_service.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

static const char *TAG = "CLOCK";

#define GPS_EPOCH_UNIX_SECONDS                  315964800LL
#define GPS_WEEK_SECONDS                        604800LL
#define GPS_WEEK_MILLISECONDS                   604800000UL

#define CLOCK_TIM_TP_WAIT_TIMEOUT_MS            750U
#define CLOCK_TIM_TP_POLL_DELAY_MS              10U
#define CLOCK_TIM_TP_MAX_AGE_US                 1500000LL
#define CLOCK_LOG_INTERVAL_US                   5000000LL

typedef struct {
    bool initialized;
    bool solution_valid;

    uint64_t anchor_capture_us;
    int64_t anchor_utc_seconds;

    uint64_t last_sample_capture_us;
    int64_t last_sample_utc_seconds;

    int64_t last_phase_error_ns;
    double frequency_ppm;

    uint32_t accepted_samples;
    uint32_t rejected_samples;
    uint32_t consecutive_rejects;

    app_leap_indicator_t leap_indicator;
    app_clock_state_t state;
} clock_context_t;

typedef struct {
    uint16_t week;
    uint32_t tow_ms;
    int64_t utc_seconds;
    int32_t quantization_error_ns;
    app_leap_indicator_t leap_indicator;
} clock_gnss_sample_t;

static clock_context_t s_clock;
static SemaphoreHandle_t s_clock_mutex;

static bool s_last_tim_tp_valid;
static uint16_t s_last_tim_tp_week;
static uint32_t s_last_tim_tp_tow_ms;

static int64_t s_last_log_us;

static bool lock_clock(void)
{
    return s_clock_mutex != NULL &&
           xSemaphoreTake(s_clock_mutex, pdMS_TO_TICKS(100U)) == pdTRUE;
}

static void unlock_clock(void)
{
    if (s_clock_mutex != NULL) {
        xSemaphoreGive(s_clock_mutex);
    }
}

static void rate_limited_log(esp_log_level_t level, const char *text)
{
    const int64_t now_us = esp_timer_get_time();

    if (now_us - s_last_log_us < CLOCK_LOG_INTERVAL_US) {
        return;
    }

    s_last_log_us = now_us;

    if (level == ESP_LOG_WARN) {
        ESP_LOGW(TAG, "%s", text);
    } else {
        ESP_LOGI(TAG, "%s", text);
    }
}

static uint32_t calculate_holdover_seconds_locked(uint64_t now_capture_us)
{
    if (!s_clock.solution_valid ||
        now_capture_us < s_clock.last_sample_capture_us) {
        return 0U;
    }

    return (uint32_t)(
        (now_capture_us - s_clock.last_sample_capture_us) / 1000000ULL);
}

static uint32_t calculate_dispersion_16_16_locked(uint32_t holdover_seconds)
{
    int64_t dispersion_ns =
        APP_CLOCK_BASE_DISPERSION_NS +
        llabs(s_clock.last_phase_error_ns);

    const double wander_ns =
        APP_CLOCK_HOLDOVER_WANDER_PPM *
        1000.0 *
        (double)holdover_seconds;

    if (wander_ns > 0.0) {
        dispersion_ns += (int64_t)wander_ns;
    }

    if (dispersion_ns > APP_CLOCK_MAX_HOLDOVER_DISPERSION_NS) {
        dispersion_ns = APP_CLOCK_MAX_HOLDOVER_DISPERSION_NS;
    }

    const uint64_t result =
        ((uint64_t)dispersion_ns * 65536ULL) / 1000000000ULL;

    return result > UINT32_MAX ? UINT32_MAX : (uint32_t)result;
}

static void publish_state_locked(void)
{
    uint64_t now_capture_us = s_clock.last_sample_capture_us;

    (void)pps_service_get_monotonic_us(&now_capture_us);

    const uint32_t holdover_seconds =
        calculate_holdover_seconds_locked(now_capture_us);

    app_state_set_clock_solution(
        s_clock.state,
        s_clock.solution_valid,
        s_clock.last_phase_error_ns,
        s_clock.frequency_ppm,
        s_clock.accepted_samples,
        s_clock.rejected_samples,
        holdover_seconds,
        calculate_dispersion_16_16_locked(holdover_seconds));
}

static bool pps_status_usable(const pps_service_status_t *status)
{
    if (status == NULL) {
        return false;
    }

    return status->interval_valid &&
           status->age_us >= 0 &&
           status->age_us <=
               ((int64_t)APP_PPS_TIMEOUT_MS * 1000LL) &&
           status->period_us >= APP_PPS_MIN_INTERVAL_US &&
           status->period_us <= APP_PPS_MAX_INTERVAL_US &&
           status->jitter_us <= APP_CLOCK_MAX_PPS_JITTER_US;
}

static void publish_pps_status(void)
{
    pps_service_status_t pps_status;

    if (!pps_service_get_status(&pps_status)) {
        return;
    }

    app_state_set_pps_status(pps_status_usable(&pps_status),
                             pps_status.last_capture_us,
                             pps_status.period_us,
                             pps_status.jitter_us,
                             pps_status.edge_count,
                             pps_status.queue_drops,
                             pps_status.age_us);
}

static bool tim_tp_is_new(const gnss_service_status_t *status)
{
    if (status == NULL || !status->timing_pulse_valid) {
        return false;
    }

    if (!s_last_tim_tp_valid) {
        return true;
    }

    return status->timing_week != s_last_tim_tp_week ||
           status->timing_tow_ms != s_last_tim_tp_tow_ms;
}

static bool tim_tp_to_utc(const gnss_service_status_t *status,
                          int64_t *out_utc_seconds)
{
    if (status == NULL ||
        out_utc_seconds == NULL ||
        !status->timing_pulse_valid ||
        !status->leap_information_valid ||
        status->current_leap_seconds < 0 ||
        status->current_leap_seconds > 64 ||
        status->timing_tow_ms >= GPS_WEEK_MILLISECONDS) {
        return false;
    }

    const int64_t gps_seconds =
        GPS_EPOCH_UNIX_SECONDS +
        ((int64_t)status->timing_week * GPS_WEEK_SECONDS) +
        ((int64_t)status->timing_tow_ms / 1000LL);

    *out_utc_seconds =
        gps_seconds - (int64_t)status->current_leap_seconds;

    return true;
}

static bool wait_for_gnss_sample(clock_gnss_sample_t *out_sample)
{
    if (out_sample == NULL) {
        return false;
    }

    const int64_t deadline_us =
        esp_timer_get_time() +
        ((int64_t)CLOCK_TIM_TP_WAIT_TIMEOUT_MS * 1000LL);

    while (esp_timer_get_time() < deadline_us) {
        gnss_service_status_t status;

        if (!gnss_service_get_status(&status)) {
            vTaskDelay(pdMS_TO_TICKS(CLOCK_TIM_TP_POLL_DELAY_MS));
            continue;
        }

        if (!status.utc_valid ||
            !status.utc_from_ubx_pvt ||
            !status.gnss_fix_valid ||
            !status.gnss_time_fully_resolved ||
            !status.leap_information_valid ||
            !status.timing_pulse_valid ||
            status.timing_pulse_age_us < 0 ||
            status.timing_pulse_age_us > CLOCK_TIM_TP_MAX_AGE_US ||
            !tim_tp_is_new(&status)) {
            vTaskDelay(pdMS_TO_TICKS(CLOCK_TIM_TP_POLL_DELAY_MS));
            continue;
        }

        int64_t utc_seconds = 0;

        if (!tim_tp_to_utc(&status, &utc_seconds)) {
            rate_limited_log(ESP_LOG_WARN,
                             "invalid TIM-TP UTC conversion state");
            return false;
        }

        /*
         * UBX-TIM-TP qErr is provided in picoseconds. Convert to
         * nanoseconds for the clock-discipline interface.
         */
        const int32_t qerr_ns =
            status.timing_quantization_error_ns / 1000;

        if (llabs((int64_t)qerr_ns) >
            APP_CLOCK_MAX_TIMING_QERR_NS) {
            rate_limited_log(ESP_LOG_WARN,
                             "TIM-TP quantization error exceeds limit");
            return false;
        }

        out_sample->week = status.timing_week;
        out_sample->tow_ms = status.timing_tow_ms;
        out_sample->utc_seconds = utc_seconds;
        out_sample->quantization_error_ns = qerr_ns;
        out_sample->leap_indicator = status.leap_indicator;

        return true;
    }

    rate_limited_log(ESP_LOG_WARN,
                     "new UBX-TIM-TP record did not arrive");

    return false;
}

static void update_reference_state(void)
{
    gnss_service_status_t gnss_status;
    pps_service_status_t pps_status;

    if (!gnss_service_get_status(&gnss_status) ||
        !pps_service_get_status(&pps_status) ||
        !lock_clock()) {
        return;
    }

    const bool gnss_ready =
        gnss_status.utc_valid &&
        gnss_status.utc_from_ubx_pvt &&
        gnss_status.gnss_fix_valid &&
        gnss_status.gnss_time_fully_resolved &&
        gnss_status.leap_information_valid &&
        gnss_status.timing_pulse_valid;

    if (!s_clock.solution_valid &&
        gnss_ready &&
        pps_status_usable(&pps_status)) {
        s_clock.state = APP_CLOCK_ACQUIRING;
    } else if (!s_clock.solution_valid &&
               (!gnss_ready || !pps_status_usable(&pps_status))) {
        s_clock.state = APP_CLOCK_UNSYNCHRONIZED;
    }

    publish_state_locked();
    unlock_clock();
}

static void enforce_holdover_policy(void)
{
    if (!lock_clock()) {
        return;
    }

    if (!s_clock.solution_valid) {
        publish_state_locked();
        unlock_clock();
        return;
    }

    uint64_t now_capture_us = 0;

    if (!pps_service_get_monotonic_us(&now_capture_us)) {
        unlock_clock();
        return;
    }

    const uint32_t holdover_seconds =
        calculate_holdover_seconds_locked(now_capture_us);

    if (holdover_seconds > APP_HOLDOVER_MAX_SECONDS) {
        s_clock.solution_valid = false;
        s_clock.state = APP_CLOCK_FAIL_CLOSED;

        ESP_LOGW(TAG,
                 "holdover limit exceeded; clock is fail-closed");
    } else if (holdover_seconds > 0U &&
               s_clock.state == APP_CLOCK_SYNCHRONIZED) {
        s_clock.state = APP_CLOCK_HOLDOVER;
    }

    publish_state_locked();
    unlock_clock();
}

static void reject_sample_locked(void)
{
    s_clock.rejected_samples++;
    s_clock.consecutive_rejects++;

    if (s_clock.consecutive_rejects >=
        APP_CLOCK_MAX_CONSECUTIVE_REJECTS) {
        s_clock.solution_valid = false;
        s_clock.state = APP_CLOCK_ACQUIRING;
        s_clock.accepted_samples = 0U;
        s_clock.frequency_ppm = 0.0;

        rate_limited_log(ESP_LOG_WARN,
                         "consecutive timing samples rejected; reacquiring");
    }

    publish_state_locked();
}

static void clock_monitor_task(void *arg)
{
    (void)arg;

    while (true) {
        pps_capture_event_t pps_event;

        if (pps_service_wait_for_capture(&pps_event, 250U)) {
            publish_pps_status();

            pps_service_status_t pps_status;

            if (pps_service_get_status(&pps_status) &&
                pps_status_usable(&pps_status)) {
                clock_gnss_sample_t gnss_sample;

                if (wait_for_gnss_sample(&gnss_sample)) {
                    const esp_err_t err =
                        clock_discipline_submit_sample(
                            pps_event.capture_us,
                            gnss_sample.utc_seconds,
                            gnss_sample.quantization_error_ns,
                            gnss_sample.leap_indicator);

                    if (err == ESP_OK) {
                        s_last_tim_tp_valid = true;
                        s_last_tim_tp_week = gnss_sample.week;
                        s_last_tim_tp_tow_ms = gnss_sample.tow_ms;
                    }
                }
            }
        } else {
            publish_pps_status();
        }

        update_reference_state();
        enforce_holdover_policy();

        vTaskDelay(pdMS_TO_TICKS(1U));
    }
}

esp_err_t clock_discipline_init(void)
{
    if (s_clock.initialized) {
        return ESP_OK;
    }

    s_clock_mutex = xSemaphoreCreateMutex();

    if (s_clock_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }

    memset(&s_clock, 0, sizeof(s_clock));

    s_clock.initialized = true;
    s_clock.state = APP_CLOCK_UNSYNCHRONIZED;
    s_clock.leap_indicator = APP_LEAP_UNKNOWN;

    s_last_tim_tp_valid = false;
    s_last_tim_tp_week = 0U;
    s_last_tim_tp_tow_ms = 0U;
    s_last_log_us = 0;

    const BaseType_t created = xTaskCreate(
        clock_monitor_task,
        "clock_discipline",
        APP_CLOCK_TASK_STACK_SIZE,
        NULL,
        APP_CLOCK_TASK_PRIORITY,
        NULL);

    if (created != pdPASS) {
        vSemaphoreDelete(s_clock_mutex);
        s_clock_mutex = NULL;
        return ESP_ERR_NO_MEM;
    }

    app_state_set_clock_solution(APP_CLOCK_UNSYNCHRONIZED,
                                 false,
                                 0,
                                 0.0,
                                 0,
                                 0,
                                 0,
                                 0);

    ESP_LOGI(TAG, "clock quality and holdover monitor started");

    return ESP_OK;
}

esp_err_t clock_discipline_submit_sample(uint64_t pps_capture_us,
                                         int64_t utc_seconds,
                                         int32_t timing_quantization_error_ns,
                                         app_leap_indicator_t leap_indicator)
{
    if (!s_clock.initialized ||
        pps_capture_us == 0U ||
        utc_seconds <= 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (llabs((int64_t)timing_quantization_error_ns) >
        APP_CLOCK_MAX_TIMING_QERR_NS) {
        if (lock_clock()) {
            reject_sample_locked();
            unlock_clock();
        }

        return ESP_ERR_INVALID_RESPONSE;
    }

    if (!lock_clock()) {
        return ESP_ERR_TIMEOUT;
    }

    if (!s_clock.solution_valid) {
        s_clock.anchor_capture_us = pps_capture_us;
        s_clock.anchor_utc_seconds = utc_seconds;

        s_clock.last_sample_capture_us = pps_capture_us;
        s_clock.last_sample_utc_seconds = utc_seconds;

        s_clock.last_phase_error_ns = timing_quantization_error_ns;
        s_clock.frequency_ppm = 0.0;

        s_clock.accepted_samples = 1U;
        s_clock.rejected_samples = 0U;
        s_clock.consecutive_rejects = 0U;

        s_clock.leap_indicator = leap_indicator;
        s_clock.state = APP_CLOCK_ACQUIRING;
        s_clock.solution_valid = true;

        publish_state_locked();
        unlock_clock();

        ESP_LOGI(TAG,
                 "accepted initial PPS/GNSS sample: utc=%" PRId64,
                 utc_seconds);

        return ESP_OK;
    }

    if (pps_capture_us <= s_clock.last_sample_capture_us ||
        utc_seconds <= s_clock.last_sample_utc_seconds) {
        reject_sample_locked();
        unlock_clock();
        return ESP_ERR_INVALID_STATE;
    }

    const uint64_t local_elapsed_us =
        pps_capture_us - s_clock.last_sample_capture_us;

    const int64_t utc_elapsed_seconds =
        utc_seconds - s_clock.last_sample_utc_seconds;

    if (utc_elapsed_seconds <= 0) {
        reject_sample_locked();
        unlock_clock();
        return ESP_ERR_INVALID_STATE;
    }

    const double expected_elapsed_us =
        (double)utc_elapsed_seconds * 1000000.0;

    const double measured_period_error_ppm =
        (((double)local_elapsed_us - expected_elapsed_us) /
         expected_elapsed_us) * 1000000.0;

    /*
     * The local counter runs fast when its measured interval exceeds one
     * UTC second. The software timebase must therefore apply the opposite
     * frequency correction.
     */
    const double target_frequency_ppm =
        -measured_period_error_ppm;

    s_clock.frequency_ppm =
        ((1.0 - APP_CLOCK_FREQUENCY_FILTER_GAIN) *
         s_clock.frequency_ppm) +
        (APP_CLOCK_FREQUENCY_FILTER_GAIN *
         target_frequency_ppm);

    if (s_clock.frequency_ppm > APP_CLOCK_MAX_FREQUENCY_PPM) {
        s_clock.frequency_ppm = APP_CLOCK_MAX_FREQUENCY_PPM;
    } else if (s_clock.frequency_ppm < -APP_CLOCK_MAX_FREQUENCY_PPM) {
        s_clock.frequency_ppm = -APP_CLOCK_MAX_FREQUENCY_PPM;
    }

    const uint64_t anchor_elapsed_us =
        pps_capture_us - s_clock.anchor_capture_us;

    const double predicted_utc_seconds =
        (double)s_clock.anchor_utc_seconds +
        ((double)anchor_elapsed_us / 1000000.0) *
            (1.0 + (s_clock.frequency_ppm / 1000000.0));

    const int64_t phase_error_ns =
        (int64_t)llround(
            ((double)utc_seconds - predicted_utc_seconds) *
            1000000000.0) +
        (int64_t)timing_quantization_error_ns;

    if (llabs(phase_error_ns) >
        APP_CLOCK_MAX_ACCEPTABLE_ERROR_NS) {
        s_clock.anchor_capture_us = pps_capture_us;
        s_clock.anchor_utc_seconds = utc_seconds;

        s_clock.last_sample_capture_us = pps_capture_us;
        s_clock.last_sample_utc_seconds = utc_seconds;

        s_clock.last_phase_error_ns = phase_error_ns;
        s_clock.frequency_ppm = 0.0;
        s_clock.accepted_samples = 1U;

        reject_sample_locked();
        unlock_clock();

        return ESP_ERR_INVALID_RESPONSE;
    }

    s_clock.anchor_capture_us = pps_capture_us;
    s_clock.anchor_utc_seconds = utc_seconds;

    s_clock.last_sample_capture_us = pps_capture_us;
    s_clock.last_sample_utc_seconds = utc_seconds;

    s_clock.last_phase_error_ns = phase_error_ns;
    s_clock.leap_indicator = leap_indicator;

    s_clock.accepted_samples++;
    s_clock.consecutive_rejects = 0U;

    if (s_clock.accepted_samples >= APP_CLOCK_LOCK_SAMPLES) {
        s_clock.state = APP_CLOCK_SYNCHRONIZED;
    } else {
        s_clock.state = APP_CLOCK_ACQUIRING;
    }

    publish_state_locked();
    unlock_clock();

    return ESP_OK;
}

bool clock_discipline_get_ntp_timestamp(clock_ntp_timestamp_t *out_timestamp)
{
    if (out_timestamp == NULL || !s_clock.initialized) {
        return false;
    }

    if (!lock_clock()) {
        return false;
    }

    if (!s_clock.solution_valid ||
        (s_clock.state != APP_CLOCK_SYNCHRONIZED &&
         s_clock.state != APP_CLOCK_HOLDOVER)) {
        unlock_clock();
        return false;
    }

    uint64_t now_capture_us = 0;

    if (!pps_service_get_monotonic_us(&now_capture_us) ||
        now_capture_us < s_clock.anchor_capture_us) {
        unlock_clock();
        return false;
    }

    const uint64_t elapsed_us =
        now_capture_us - s_clock.anchor_capture_us;

    const double utc_seconds =
        (double)s_clock.anchor_utc_seconds +
        ((double)elapsed_us / 1000000.0) *
            (1.0 + (s_clock.frequency_ppm / 1000000.0));

    if (utc_seconds < 0.0) {
        unlock_clock();
        return false;
    }

    const uint64_t integer_seconds = (uint64_t)utc_seconds;
    const double fractional_seconds =
        utc_seconds - (double)integer_seconds;

    out_timestamp->seconds =
        (uint32_t)(integer_seconds + APP_NTP_EPOCH_DELTA);

    out_timestamp->fraction =
        (uint32_t)(fractional_seconds * 4294967296.0);

    unlock_clock();

    return true;
}

bool clock_discipline_get_status(clock_discipline_status_t *out_status)
{
    if (out_status == NULL || !s_clock.initialized) {
        return false;
    }

    if (!lock_clock()) {
        return false;
    }

    uint64_t now_capture_us = s_clock.last_sample_capture_us;

    (void)pps_service_get_monotonic_us(&now_capture_us);

    const uint32_t holdover_seconds =
        calculate_holdover_seconds_locked(now_capture_us);

    out_status->initialized = s_clock.initialized;
    out_status->solution_valid = s_clock.solution_valid;
    out_status->state = s_clock.state;
    out_status->phase_error_ns = s_clock.last_phase_error_ns;
    out_status->frequency_ppm = s_clock.frequency_ppm;
    out_status->accepted_samples = s_clock.accepted_samples;
    out_status->rejected_samples = s_clock.rejected_samples;
    out_status->holdover_seconds = holdover_seconds;
    out_status->root_dispersion_16_16 =
        calculate_dispersion_16_16_locked(holdover_seconds);

    unlock_clock();

    return true;
}