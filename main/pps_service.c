#include "pps_service.h"

#include <inttypes.h>
#include <stdlib.h>

#include "app_config.h"

#include "driver/gpio.h"
#include "driver/gpio_etm.h"
#include "driver/gptimer.h"
#include "driver/gptimer_etm.h"

#include "esp_check.h"
#include "esp_err.h"
#include "esp_etm.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/queue.h"

static const char *TAG = "PPS";

static gptimer_handle_t s_gptimer;
static esp_etm_event_handle_t s_gpio_etm_event;
static esp_etm_task_handle_t s_gptimer_capture_task;
static esp_etm_channel_handle_t s_etm_channel;

static QueueHandle_t s_capture_queue;
static portMUX_TYPE s_pps_lock = portMUX_INITIALIZER_UNLOCKED;

static pps_service_status_t s_status;
static uint64_t s_previous_capture_us;

static uint64_t ticks_to_us(uint64_t ticks)
{
    return (ticks * 1000000ULL) / APP_PPS_TIMER_RESOLUTION_HZ;
}

static void IRAM_ATTR pps_gpio_isr(void *arg)
{
    (void)arg;

    if (s_gptimer == NULL || s_capture_queue == NULL) {
        return;
    }

    uint64_t captured_ticks = 0;

    /*
     * The ETM task has already latched the timer value on the GPIO rising
     * edge. The ISR reads that captured value and queues it for task context.
     */
    if (gptimer_get_captured_count(s_gptimer, &captured_ticks) != ESP_OK) {
        return;
    }

    const pps_capture_event_t event = {
        .capture_ticks = captured_ticks,
        .capture_us = ticks_to_us(captured_ticks),
    };

    BaseType_t higher_priority_task_woken = pdFALSE;

    if (xQueueSendFromISR(s_capture_queue,
                          &event,
                          &higher_priority_task_woken) != pdTRUE) {
        portENTER_CRITICAL_ISR(&s_pps_lock);
        s_status.queue_drops++;
        portEXIT_CRITICAL_ISR(&s_pps_lock);
    }

    if (higher_priority_task_woken == pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

static esp_err_t pps_configure_gptimer(void)
{
    const gptimer_config_t timer_config = {
        .clk_src = GPTIMER_CLK_SRC_DEFAULT,
        .direction = GPTIMER_COUNT_UP,
        .resolution_hz = APP_PPS_TIMER_RESOLUTION_HZ,
        .flags = {
            .intr_shared = false,
            .allow_pd = false,
        },
    };

    ESP_RETURN_ON_ERROR(gptimer_new_timer(&timer_config, &s_gptimer),
                        TAG,
                        "create GPTimer");

    ESP_RETURN_ON_ERROR(gptimer_enable(s_gptimer),
                        TAG,
                        "enable GPTimer");

    ESP_RETURN_ON_ERROR(gptimer_start(s_gptimer),
                        TAG,
                        "start GPTimer");

    return ESP_OK;
}

static esp_err_t pps_configure_etm_capture(void)
{
    const gpio_etm_event_config_t gpio_event_config = {
        .edge = GPIO_ETM_EVENT_EDGE_POS,
    };

    ESP_RETURN_ON_ERROR(gpio_new_etm_event(&gpio_event_config,
                                           &s_gpio_etm_event),
                        TAG,
                        "create GPIO ETM event");

    ESP_RETURN_ON_ERROR(gpio_etm_event_bind_gpio(s_gpio_etm_event,
                                                 APP_PPS_GPIO),
                        TAG,
                        "bind GPIO ETM event");

    const gptimer_etm_task_config_t capture_task_config = {
        .task_type = GPTIMER_ETM_TASK_CAPTURE,
    };

    ESP_RETURN_ON_ERROR(gptimer_new_etm_task(s_gptimer,
                                             &capture_task_config,
                                             &s_gptimer_capture_task),
                        TAG,
                        "create GPTimer capture task");

    const esp_etm_channel_config_t channel_config = {0};

    ESP_RETURN_ON_ERROR(esp_etm_new_channel(&channel_config,
                                             &s_etm_channel),
                        TAG,
                        "create ETM channel");

    ESP_RETURN_ON_ERROR(esp_etm_channel_connect(s_etm_channel,
                                                s_gpio_etm_event,
                                                s_gptimer_capture_task),
                        TAG,
                        "connect ETM event and task");

    ESP_RETURN_ON_ERROR(esp_etm_channel_enable(s_etm_channel),
                        TAG,
                        "enable ETM channel");

    return ESP_OK;
}

static esp_err_t pps_configure_gpio_interrupt(void)
{
    /*
     * Do not name this variable gpio_config. That would shadow the ESP-IDF
     * gpio_config() function.
     */
    const gpio_config_t pps_gpio_config = {
        .pin_bit_mask = (1ULL << APP_PPS_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_POSEDGE,
    };

    ESP_RETURN_ON_ERROR(gpio_config(&pps_gpio_config),
                        TAG,
                        "configure PPS GPIO");

    esp_err_t err = gpio_install_isr_service(ESP_INTR_FLAG_IRAM);

    /*
     * A different service may already have installed the shared GPIO ISR
     * service. That condition is acceptable.
     */
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }

    return gpio_isr_handler_add((gpio_num_t)APP_PPS_GPIO,
                                pps_gpio_isr,
                                NULL);
}

esp_err_t pps_service_init(void)
{
    if (s_status.initialized) {
        return ESP_OK;
    }

    s_capture_queue = xQueueCreate(APP_PPS_EVENT_QUEUE_LENGTH,
                                   sizeof(pps_capture_event_t));

    if (s_capture_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ESP_RETURN_ON_ERROR(pps_configure_gptimer(),
                        TAG,
                        "configure GPTimer");

    ESP_RETURN_ON_ERROR(pps_configure_etm_capture(),
                        TAG,
                        "configure ETM capture");

    ESP_RETURN_ON_ERROR(pps_configure_gpio_interrupt(),
                        TAG,
                        "configure GPIO interrupt");

    portENTER_CRITICAL(&s_pps_lock);

    s_status.initialized = true;
    s_status.etm_active = true;
    s_status.interval_valid = false;

    portEXIT_CRITICAL(&s_pps_lock);

    ESP_LOGI(TAG,
             "PPS ETM capture active: GPIO=%d resolution=%u Hz",
             APP_PPS_GPIO,
             APP_PPS_TIMER_RESOLUTION_HZ);

    return ESP_OK;
}

bool pps_service_wait_for_capture(pps_capture_event_t *out_event,
                                  uint32_t timeout_ms)
{
    if (out_event == NULL || s_capture_queue == NULL) {
        return false;
    }

    if (xQueueReceive(s_capture_queue,
                      out_event,
                      pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        return false;
    }

    bool first_capture = false;
    bool interval_valid = false;
    uint32_t period_us = 0U;
    uint32_t jitter_us = 0U;

    if (s_previous_capture_us == 0U) {
        /*
         * First PPS edge after startup. No interval can be calculated yet.
         * This is expected and must not be logged as an invalid PPS interval.
         */
        first_capture = true;
    } else if (out_event->capture_us > s_previous_capture_us) {
        const uint64_t period_64 =
            out_event->capture_us - s_previous_capture_us;

        if (period_64 <= UINT32_MAX) {
            period_us = (uint32_t)period_64;

            if (period_64 >= APP_PPS_MIN_INTERVAL_US &&
                period_64 <= APP_PPS_MAX_INTERVAL_US) {
                interval_valid = true;

                jitter_us = (uint32_t)llabs(
                    (long long)period_64 -
                    (long long)APP_PPS_NOMINAL_INTERVAL_US);
            }
        }
    }

    s_previous_capture_us = out_event->capture_us;

    portENTER_CRITICAL(&s_pps_lock);

    s_status.last_capture_us = out_event->capture_us;
    s_status.period_us = period_us;
    s_status.jitter_us = jitter_us;
    s_status.edge_count++;

    if (first_capture) {
        s_status.interval_valid = false;
    } else if (interval_valid) {
        s_status.interval_valid = true;
        s_status.valid_interval_count++;
    } else {
        s_status.interval_valid = false;
        s_status.invalid_interval_count++;
    }

    portEXIT_CRITICAL(&s_pps_lock);

    if (!first_capture && !interval_valid) {
        ESP_LOGW(TAG,
                 "invalid PPS interval: %" PRIu32
                 " us, capture=%" PRIu64
                 " us; expected=%" PRIu64 "..%" PRIu64 " us",
                 period_us,
                 out_event->capture_us,
                 APP_PPS_MIN_INTERVAL_US,
                 APP_PPS_MAX_INTERVAL_US);
    }

    return true;
}

bool pps_service_get_monotonic_us(uint64_t *out_us)
{
    if (out_us == NULL || s_gptimer == NULL) {
        return false;
    }

    uint64_t raw_ticks = 0;

    if (gptimer_get_raw_count(s_gptimer, &raw_ticks) != ESP_OK) {
        return false;
    }

    *out_us = ticks_to_us(raw_ticks);
    return true;
}

bool pps_service_get_status(pps_service_status_t *out_status)
{
    if (out_status == NULL) {
        return false;
    }

    pps_service_status_t local_status;

    portENTER_CRITICAL(&s_pps_lock);
    local_status = s_status;
    portEXIT_CRITICAL(&s_pps_lock);

    uint64_t now_us = 0;

    if (pps_service_get_monotonic_us(&now_us) &&
        local_status.last_capture_us != 0U &&
        now_us >= local_status.last_capture_us) {
        local_status.age_us =
            (int64_t)(now_us - local_status.last_capture_us);
    } else {
        local_status.age_us = -1;
    }

    *out_status = local_status;
    return true;
}