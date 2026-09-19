#include "hp_lp_test.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "driver/rtc_io.h"

#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "ulp_lp_core.h"
#include "ulp_lp_core_lp_timer_shared.h"
#include "lp_core_mailbox.h"

#include "pps_service.h"

#include "ulp_hp_lp_test.h"

static const char *TAG = "HP_LP_TEST";

#define HP_LP_PPS_GPIO GPIO_NUM_4

#define HP_LP_PPS_COMPARE_SECONDS 60U
#define HP_LP_PPS_COMPARE_MS      (HP_LP_PPS_COMPARE_SECONDS * 1000U)

#define HP_LP_CMD_MAILBOX_PROOF          ((lp_message_t)0x1234)
#define HP_LP_CMD_SET_PPS_EXPECTED_TICKS ((lp_message_t)0x2000)

#define HP_LP_PPS_TELEMETRY_READ_RETRIES 100U

#define HP_LP_PPS_HEALTH_UNKNOWN 0U
#define HP_LP_PPS_HEALTH_HEALTHY 1U
#define HP_LP_PPS_HEALTH_LOST    2U

#define HP_LP_PPS_WATCHDOG_OBSERVE_SECONDS 30U

extern const uint8_t ulp_hp_lp_test_bin_start[]
    asm("_binary_ulp_hp_lp_test_bin_start");

extern const uint8_t ulp_hp_lp_test_bin_end[]
    asm("_binary_ulp_hp_lp_test_bin_end");

typedef struct {
    uint32_t sequence;
    uint32_t pps_count;

    uint64_t last_tick;
    uint64_t period_ticks;

    uint32_t interval_count;
    uint32_t expected_ticks;

    uint32_t period_error_ticks;
    bool interval_valid;

    uint32_t valid_interval_count;
    uint32_t invalid_interval_count;

    uint32_t health;

    uint64_t watchdog_age_ticks;
    uint64_t watchdog_timeout_ticks;

    uint32_t loss_count;
    uint32_t recovery_count;

    uint32_t isr_timing_sample_count;
    uint32_t isr_latest_cycles;
    uint32_t isr_min_cycles;
    uint32_t isr_max_cycles;
    uint64_t isr_sum_cycles;
} hp_lp_pps_telemetry_t;

static uint64_t hp_lp_make_u64(uint32_t hi, uint32_t lo)
{
    return ((uint64_t)hi << 32) |
           (uint64_t)lo;
}

static const char *hp_lp_pps_health_name(
    uint32_t health)
{
    switch (health) {
    case HP_LP_PPS_HEALTH_HEALTHY:
        return "HEALTHY";

    case HP_LP_PPS_HEALTH_LOST:
        return "LOST";

    default:
        return "UNKNOWN";
    }
}

static bool hp_lp_read_pps_telemetry(
    hp_lp_pps_telemetry_t *out)
{
    if (out == NULL) {
        return false;
    }

    for (uint32_t attempt = 0;
         attempt < HP_LP_PPS_TELEMETRY_READ_RETRIES;
         ++attempt) {

        const uint32_t seq_start =
            ulp_hp_lp_pps_telemetry_seq;

        /*
         * Odd means LP is currently modifying the telemetry.
         */
        if ((seq_start & 1U) != 0U) {
            continue;
        }

        const uint32_t pps_count =
            ulp_hp_lp_pps_count;

        const uint32_t last_tick_lo =
            ulp_hp_lp_pps_last_tick_lo;

        const uint32_t last_tick_hi =
            ulp_hp_lp_pps_last_tick_hi;

        const uint32_t period_ticks_lo =
            ulp_hp_lp_pps_period_ticks_lo;

        const uint32_t period_ticks_hi =
            ulp_hp_lp_pps_period_ticks_hi;

        const uint32_t interval_count =
            ulp_hp_lp_pps_interval_count;

        const uint32_t expected_ticks =
            ulp_hp_lp_pps_expected_ticks;

        const uint32_t period_error_ticks =
            ulp_hp_lp_pps_period_error_ticks;

        const uint32_t interval_valid =
            ulp_hp_lp_pps_interval_valid;

        const uint32_t valid_interval_count =
            ulp_hp_lp_pps_valid_interval_count;

        const uint32_t invalid_interval_count =
            ulp_hp_lp_pps_invalid_interval_count;

        const uint32_t health =
            ulp_hp_lp_pps_health;

        const uint32_t watchdog_age_ticks_lo =
            ulp_hp_lp_pps_watchdog_age_ticks_lo;

        const uint32_t watchdog_age_ticks_hi =
            ulp_hp_lp_pps_watchdog_age_ticks_hi;

        const uint32_t watchdog_timeout_ticks_lo =
            ulp_hp_lp_pps_watchdog_timeout_ticks_lo;

        const uint32_t watchdog_timeout_ticks_hi =
            ulp_hp_lp_pps_watchdog_timeout_ticks_hi;

        const uint32_t loss_count =
            ulp_hp_lp_pps_loss_count;

        const uint32_t recovery_count =
            ulp_hp_lp_pps_recovery_count;

        const uint32_t isr_timing_sample_count =
            ulp_hp_lp_pps_isr_timing_sample_count;

        const uint32_t isr_latest_cycles =
            ulp_hp_lp_pps_isr_latest_cycles;

        const uint32_t isr_min_cycles =
            ulp_hp_lp_pps_isr_min_cycles;

        const uint32_t isr_max_cycles =
            ulp_hp_lp_pps_isr_max_cycles;

        const uint32_t isr_sum_cycles_lo =
            ulp_hp_lp_pps_isr_sum_cycles_lo;

        const uint32_t isr_sum_cycles_hi =
            ulp_hp_lp_pps_isr_sum_cycles_hi;

        const uint32_t seq_end =
            ulp_hp_lp_pps_telemetry_seq;

        if (seq_start != seq_end ||
            (seq_end & 1U) != 0U) {
            continue;
        }

        out->sequence =
            seq_end;

        out->pps_count =
            pps_count;

        out->last_tick =
            hp_lp_make_u64(
                last_tick_hi,
                last_tick_lo);

        out->period_ticks =
            hp_lp_make_u64(
                period_ticks_hi,
                period_ticks_lo);

        out->interval_count =
            interval_count;

        out->expected_ticks =
            expected_ticks;

        out->period_error_ticks =
            period_error_ticks;

        out->interval_valid =
            (interval_valid != 0U);

        out->valid_interval_count =
            valid_interval_count;

        out->invalid_interval_count =
            invalid_interval_count;

        out->health =
            health;

        out->watchdog_age_ticks =
            hp_lp_make_u64(
                watchdog_age_ticks_hi,
                watchdog_age_ticks_lo);

        out->watchdog_timeout_ticks =
            hp_lp_make_u64(
                watchdog_timeout_ticks_hi,
                watchdog_timeout_ticks_lo);

        out->loss_count =
            loss_count;

        out->recovery_count =
            recovery_count;

        out->isr_timing_sample_count =
            isr_timing_sample_count;

        out->isr_latest_cycles =
            isr_latest_cycles;

        out->isr_min_cycles =
            isr_min_cycles;

        out->isr_max_cycles =
            isr_max_cycles;

        out->isr_sum_cycles =
            hp_lp_make_u64(
                isr_sum_cycles_hi,
                isr_sum_cycles_lo);

        return true;
    }

    return false;
}

static void hp_lp_pps_compare_task(void *arg)
{
    (void)arg;

    pps_service_status_t hp_start = {0};
    pps_service_status_t hp_end = {0};

    while (true) {
        if (pps_service_get_status(&hp_start) &&
            hp_start.initialized &&
            hp_start.etm_active &&
            hp_start.edge_count > 0U) {
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }

    hp_lp_pps_telemetry_t lp_start_snapshot = {0};

    if (!hp_lp_read_pps_telemetry(
            &lp_start_snapshot)) {
        ESP_LOGE(TAG,
                 "HP-LP PPS comparison failed: "
                 "unable to obtain coherent LP start telemetry");
        vTaskDelete(NULL);
        return;
    }

    const uint32_t lp_start =
        lp_start_snapshot.pps_count;

    ESP_LOGI(TAG,
             "HP-LP PPS comparison start: duration=%u s "
             "HP=%" PRIu32 " LP=%" PRIu32 " drops=%" PRIu32,
             (unsigned)HP_LP_PPS_COMPARE_SECONDS,
             hp_start.edge_count,
             lp_start,
             hp_start.queue_drops);

    vTaskDelay(
        pdMS_TO_TICKS(
            HP_LP_PPS_COMPARE_MS));

    if (!pps_service_get_status(&hp_end)) {
        ESP_LOGE(TAG,
                 "HP-LP PPS comparison failed: "
                 "unable to read HP PPS status");
        vTaskDelete(NULL);
        return;
    }

    hp_lp_pps_telemetry_t lp_end_snapshot = {0};

    if (!hp_lp_read_pps_telemetry(
            &lp_end_snapshot)) {
        ESP_LOGE(TAG,
                 "HP-LP PPS comparison failed: "
                 "unable to obtain coherent LP end telemetry");
        vTaskDelete(NULL);
        return;
    }

    const uint32_t lp_end =
        lp_end_snapshot.pps_count;

    const uint32_t hp_delta =
        hp_end.edge_count -
        hp_start.edge_count;

    const uint32_t lp_delta =
        lp_end -
        lp_start;

    const uint32_t drop_delta =
        hp_end.queue_drops -
        hp_start.queue_drops;

    const int32_t edge_error =
        (int32_t)lp_delta -
        (int32_t)hp_delta;

    ESP_LOGI(TAG,
             "HP-LP PPS comparison end: "
             "HP=%" PRIu32 "->%" PRIu32 " delta=%" PRIu32 " "
             "LP=%" PRIu32 "->%" PRIu32 " delta=%" PRIu32 " "
             "error=%" PRId32 " drops=%" PRIu32,
             hp_start.edge_count,
             hp_end.edge_count,
             hp_delta,
             lp_start,
             lp_end,
             lp_delta,
             edge_error,
             drop_delta);

    ESP_LOGI(TAG,
             "LP PPS coherent telemetry: "
             "seq=%" PRIu32 " "
             "last_tick=%" PRIu64 " "
             "period_ticks=%" PRIu64 " "
             "intervals=%" PRIu32 " "
             "expected_ticks=%" PRIu32,
             lp_end_snapshot.sequence,
             lp_end_snapshot.last_tick,
             lp_end_snapshot.period_ticks,
             lp_end_snapshot.interval_count,
             lp_end_snapshot.expected_ticks);

    ESP_LOGI(TAG,
             "LP PPS qualification: "
             "valid=%u "
             "error_ticks=%" PRIu32 " "
             "valid_intervals=%" PRIu32 " "
             "invalid_intervals=%" PRIu32,
             lp_end_snapshot.interval_valid ? 1U : 0U,
             lp_end_snapshot.period_error_ticks,
             lp_end_snapshot.valid_interval_count,
             lp_end_snapshot.invalid_interval_count);

    ESP_LOGI(TAG,
             "LP PPS watchdog: "
             "health=%s "
             "age_ticks=%" PRIu64 " "
             "timeout_ticks=%" PRIu64 " "
             "losses=%" PRIu32 " "
             "recoveries=%" PRIu32,
             hp_lp_pps_health_name(
                 lp_end_snapshot.health),
             lp_end_snapshot.watchdog_age_ticks,
             lp_end_snapshot.watchdog_timeout_ticks,
             lp_end_snapshot.loss_count,
             lp_end_snapshot.recovery_count);

    if (hp_delta == lp_delta &&
        drop_delta == 0U) {
        ESP_LOGI(TAG,
                 "HP-LP sustained PPS edge-count comparison PASS");
    } else {
        ESP_LOGE(TAG,
                 "HP-LP sustained PPS edge-count comparison FAIL");
    }

    if (lp_end_snapshot.interval_valid &&
        lp_end_snapshot.valid_interval_count > 0U &&
        lp_end_snapshot.invalid_interval_count == 0U) {
        ESP_LOGI(TAG,
                 "LP PPS interval qualification PASS");
    } else {
        ESP_LOGE(TAG,
                 "LP PPS interval qualification FAIL");
    }

    if (lp_end_snapshot.health ==
            HP_LP_PPS_HEALTH_HEALTHY &&
        lp_end_snapshot.watchdog_timeout_ticks > 0ULL &&
        lp_end_snapshot.watchdog_age_ticks <
            lp_end_snapshot.watchdog_timeout_ticks &&
        lp_end_snapshot.loss_count == 0U &&
        lp_end_snapshot.recovery_count == 0U) {

        ESP_LOGI(TAG,
                 "LP PPS watchdog healthy-baseline PASS");
    } else {
        ESP_LOGE(TAG,
                 "LP PPS watchdog healthy-baseline FAIL");
    }

    if (lp_end_snapshot.isr_timing_sample_count > 0U) {
        const uint64_t average_cycles_x1000 =
            (lp_end_snapshot.isr_sum_cycles * 1000ULL) /
            (uint64_t)lp_end_snapshot.isr_timing_sample_count;

        ESP_LOGI(TAG,
                 "LP PPS ISR timing: "
                 "samples=%" PRIu32 " "
                 "latest_cycles=%" PRIu32 " "
                 "min_cycles=%" PRIu32 " "
                 "max_cycles=%" PRIu32 " "
                 "avg_cycles=%" PRIu64 ".%03" PRIu64,
                 lp_end_snapshot.isr_timing_sample_count,
                 lp_end_snapshot.isr_latest_cycles,
                 lp_end_snapshot.isr_min_cycles,
                 lp_end_snapshot.isr_max_cycles,
                 average_cycles_x1000 / 1000ULL,
                 average_cycles_x1000 % 1000ULL);

        ESP_LOGI(TAG,
                 "HP-LP.7A LP PPS ISR service-time measurement PASS");
    } else {
        ESP_LOGE(TAG,
                 "HP-LP.7A LP PPS ISR service-time measurement FAIL: "
                 "no timing samples");
    }

    ESP_LOGW(TAG,
             "HP-LP PPS watchdog fault observation ACTIVE for %u s: "
             "keep GPIO5 connected; disconnect/reconnect GPIO4 only",
             (unsigned)HP_LP_PPS_WATCHDOG_OBSERVE_SECONDS);

    bool saw_lost = false;
    bool saw_recovered = false;

    for (uint32_t second = 1U;
         second <= HP_LP_PPS_WATCHDOG_OBSERVE_SECONDS;
         ++second) {

        vTaskDelay(pdMS_TO_TICKS(1000));

        hp_lp_pps_telemetry_t observation = {0};

        if (!hp_lp_read_pps_telemetry(
                &observation)) {
            ESP_LOGE(TAG,
                     "LP PPS watchdog observe: "
                     "unable to obtain coherent telemetry");
            continue;
        }

        pps_service_status_t hp_observe = {0};
        const bool hp_status_ok =
            pps_service_get_status(&hp_observe);

        ESP_LOGI(TAG,
                 "LP PPS watchdog observe: "
                 "t=%" PRIu32 "s "
                 "health=%s "
                 "age_ticks=%" PRIu64 " "
                 "timeout_ticks=%" PRIu64 " "
                 "losses=%" PRIu32 " "
                 "recoveries=%" PRIu32 " "
                 "HP_valid=%u "
                 "HP_drops=%" PRIu32,
                 second,
                 hp_lp_pps_health_name(
                     observation.health),
                 observation.watchdog_age_ticks,
                 observation.watchdog_timeout_ticks,
                 observation.loss_count,
                 observation.recovery_count,
                (hp_status_ok &&
                  hp_observe.initialized &&
                  hp_observe.etm_active) ? 1U : 0U,
                 hp_status_ok ?
                     hp_observe.queue_drops :
                     UINT32_MAX);

        if (observation.health ==
                HP_LP_PPS_HEALTH_LOST &&
            observation.loss_count >= 1U) {

            saw_lost = true;
        }

        if (saw_lost &&
            observation.health ==
                HP_LP_PPS_HEALTH_HEALTHY &&
            observation.loss_count >= 1U &&
            observation.recovery_count >= 1U) {

            saw_recovered = true;
        }
    }

    if (saw_lost &&
        saw_recovered) {
        ESP_LOGI(TAG,
                 "LP PPS watchdog loss/recovery proof PASS");
    } else {
        ESP_LOGE(TAG,
                 "LP PPS watchdog loss/recovery proof FAIL: "
                 "saw_lost=%u saw_recovered=%u",
                 saw_lost ? 1U : 0U,
                 saw_recovered ? 1U : 0U);
    }

    vTaskDelete(NULL);
}

esp_err_t hp_lp_test_start(void)
{
    ESP_RETURN_ON_ERROR(
        rtc_gpio_init(HP_LP_PPS_GPIO),
        TAG,
        "initialize LP PPS GPIO");

    ESP_RETURN_ON_ERROR(
        rtc_gpio_set_direction(
            HP_LP_PPS_GPIO,
            RTC_GPIO_MODE_INPUT_ONLY),
        TAG,
        "configure LP PPS GPIO input");

    ESP_RETURN_ON_ERROR(
        rtc_gpio_pullup_dis(
            HP_LP_PPS_GPIO),
        TAG,
        "disable LP PPS GPIO pull-up");

    ESP_RETURN_ON_ERROR(
        rtc_gpio_pulldown_dis(
            HP_LP_PPS_GPIO),
        TAG,
        "disable LP PPS GPIO pull-down");

    ESP_LOGI(TAG,
             "LP passive PPS observer configured: GPIO=%d",
             (int)HP_LP_PPS_GPIO);

    const size_t binary_size =
        (size_t)(
            ulp_hp_lp_test_bin_end -
            ulp_hp_lp_test_bin_start);

    ESP_LOGI(TAG,
             "Loading LP-core test binary: %u bytes",
             (unsigned)binary_size);

    esp_err_t err =
        ulp_lp_core_load_binary(
            ulp_hp_lp_test_bin_start,
            binary_size);

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "LP-core binary load failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    ulp_lp_core_cfg_t cfg = {
        .wakeup_source =
            ULP_LP_CORE_WAKEUP_SOURCE_HP_CPU,
    };

    err = ulp_lp_core_run(&cfg);

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "LP-core start failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG,
             "LP core started");

    vTaskDelay(
        pdMS_TO_TICKS(100));

    const uint32_t magic =
        ulp_hp_lp_magic;

    if (magic != 0x4C50434FUL) {
        ESP_LOGE(TAG,
                 "LP execution proof failed: "
                 "magic=0x%08" PRIX32,
                 magic);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG,
             "LP execution proof PASS: "
             "magic=0x%08" PRIX32,
             magic);

    lp_mailbox_t mailbox = NULL;

    err = lp_core_mailbox_init(
        &mailbox,
        NULL);

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "HP mailbox initialization failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG,
             "HP mailbox initialized");

    /*
     * Preserve the original HP-LP.2 mailbox proof.
     */
    const lp_message_t command =
        HP_LP_CMD_MAILBOX_PROOF;

    ESP_LOGI(TAG,
             "HP -> LP command: 0x%" PRIXPTR,
             (uintptr_t)command);

    err = lp_core_mailbox_send(
        mailbox,
        command,
        pdMS_TO_TICKS(1000));

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "HP -> LP mailbox send failed: %s",
                 esp_err_to_name(err));
        lp_core_mailbox_deinit(mailbox);
        return err;
    }

    lp_message_t response = 0;

    err = lp_core_mailbox_receive(
        mailbox,
        &response,
        pdMS_TO_TICKS(1000));

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "LP -> HP mailbox receive failed: %s",
                 esp_err_to_name(err));
        lp_core_mailbox_deinit(mailbox);
        return err;
    }

    ESP_LOGI(TAG,
             "LP -> HP response: 0x%" PRIXPTR,
             (uintptr_t)response);

    if (response !=
        (HP_LP_CMD_MAILBOX_PROOF + 1)) {
        ESP_LOGE(TAG,
                 "HP-LP mailbox proof failed: "
                 "expected=0x1235");
        lp_core_mailbox_deinit(mailbox);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG,
             "HP-LP mailbox proof PASS");

    /*
     * Obtain the calibrated number of RTC slow-clock ticks corresponding
     * to one second using the ESP-IDF LP timer conversion.
     */
    const uint64_t expected_ticks_64 =
        ulp_lp_core_lp_timer_calculate_sleep_ticks(
            1000000ULL);

    if (expected_ticks_64 == 0ULL ||
        expected_ticks_64 > UINT32_MAX) {
        ESP_LOGE(TAG,
                 "Invalid calibrated LP PPS expected ticks: "
                 "%" PRIu64,
                 expected_ticks_64);
        lp_core_mailbox_deinit(mailbox);
        return ESP_FAIL;
    }

    const lp_message_t expected_ticks =
        (lp_message_t)
        (uint32_t)expected_ticks_64;

    ESP_LOGI(TAG,
             "LP PPS calibrated expected interval: "
             "%" PRIu32 " ticks",
             (uint32_t)expected_ticks);

    err = lp_core_mailbox_send(
        mailbox,
        HP_LP_CMD_SET_PPS_EXPECTED_TICKS,
        pdMS_TO_TICKS(1000));

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "LP PPS configuration command send failed: %s",
                 esp_err_to_name(err));
        lp_core_mailbox_deinit(mailbox);
        return err;
    }

    err = lp_core_mailbox_send(
        mailbox,
        expected_ticks,
        pdMS_TO_TICKS(1000));

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "LP PPS expected-ticks send failed: %s",
                 esp_err_to_name(err));
        lp_core_mailbox_deinit(mailbox);
        return err;
    }

    response = 0;

    err = lp_core_mailbox_receive(
        mailbox,
        &response,
        pdMS_TO_TICKS(1000));

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "LP PPS configuration response failed: %s",
                 esp_err_to_name(err));
        lp_core_mailbox_deinit(mailbox);
        return err;
    }

    if (response != expected_ticks) {
        ESP_LOGE(TAG,
                 "LP PPS configuration verification failed: "
                 "sent=%" PRIu32 " received=%" PRIu32,
                 (uint32_t)expected_ticks,
                 (uint32_t)response);
        lp_core_mailbox_deinit(mailbox);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG,
             "LP PPS calibrated interval configuration PASS");

    lp_core_mailbox_deinit(mailbox);

    const uint32_t initial_pps_count =
        ulp_hp_lp_pps_count;

    ESP_LOGI(TAG,
             "LP PPS observer initial count: %" PRIu32,
             initial_pps_count);

    vTaskDelay(
        pdMS_TO_TICKS(2200));

    const uint32_t final_pps_count =
        ulp_hp_lp_pps_count;

    ESP_LOGI(TAG,
             "LP PPS observer: GPIO=%d "
             "count=%" PRIu32 " -> %" PRIu32
             " delta=%" PRIu32,
             (int)HP_LP_PPS_GPIO,
             initial_pps_count,
             final_pps_count,
             final_pps_count -
                 initial_pps_count);

    if (final_pps_count <=
        initial_pps_count) {
        ESP_LOGE(TAG,
                 "LP passive PPS observation failed: "
                 "no rising edges observed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG,
             "LP passive PPS observation PASS");

    return ESP_OK;
}

esp_err_t hp_lp_test_start_pps_comparison(void)
{
    BaseType_t task_result =
        xTaskCreate(
            hp_lp_pps_compare_task,
            "hp_lp_pps_cmp",
            3072,
            NULL,
            3,
            NULL);

    if (task_result != pdPASS) {
        ESP_LOGE(TAG,
                 "Failed to create HP-LP PPS comparison task");
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG,
             "HP-LP sustained PPS comparison task started");

    return ESP_OK;
}