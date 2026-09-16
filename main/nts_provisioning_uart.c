#include "nts_provisioning_uart.h"

#include <stdlib.h>
#include <string.h>

#include "app_config.h"
#include "nts_provisioning.h"

#include "driver/uart.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define NTS_PROVISION_UART_NUM \
	((uart_port_t)APP_NTS_PROVISION_UART)
#define NTS_PROVISION_TASK_STACK_SIZE   6144U
#define NTS_PROVISION_TASK_PRIORITY     5U

#define NTS_PROVISION_RX_BUFFER_SIZE    2048U
#define NTS_PROVISION_LINE_MAX_LEN      256U

#define NTS_PROVISION_CERT_MAX_LEN      8192U
#define NTS_PROVISION_KEY_MAX_LEN       8192U

typedef enum {
    NTS_PROVISION_IDLE = 0,
    NTS_PROVISION_CERT,
    NTS_PROVISION_KEY,
} nts_provision_state_t;

static const char *TAG = "NTS_PROVISION";

static nts_provision_state_t s_state;

static uint8_t *s_buffer;
static size_t s_buffer_len;
static size_t s_buffer_capacity;

static void secure_free_buffer(void)
{
    if (s_buffer != NULL) {
        volatile uint8_t *ptr =
            (volatile uint8_t *)s_buffer;

        for (size_t i = 0U;
             i < s_buffer_capacity;
             i++) {
            ptr[i] = 0U;
        }

        free(s_buffer);
    }

    s_buffer = NULL;
    s_buffer_len = 0U;
    s_buffer_capacity = 0U;
    s_state = NTS_PROVISION_IDLE;
}

static esp_err_t begin_buffer(
    nts_provision_state_t state,
    size_t capacity)
{
    secure_free_buffer();

    s_buffer = calloc(1U, capacity);

    if (s_buffer == NULL) {
        return ESP_ERR_NO_MEM;
    }

    s_buffer_capacity = capacity;
    s_buffer_len = 0U;
    s_state = state;

    return ESP_OK;
}

static esp_err_t append_line(
    const char *line)
{
    if (line == NULL ||
        s_buffer == NULL ||
        s_state == NTS_PROVISION_IDLE) {
        return ESP_ERR_INVALID_STATE;
    }

    size_t line_len = strlen(line);

    if ((s_buffer_len + line_len + 1U) >=
        s_buffer_capacity) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(
        &s_buffer[s_buffer_len],
        line,
        line_len);

    s_buffer_len += line_len;

    s_buffer[s_buffer_len++] = '\n';

    return ESP_OK;
}

static void print_status(void)
{
    nts_provisioning_status_t status;

    esp_err_t err =
        nts_provisioning_get_status(&status);

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Status failed: %s",
                 esp_err_to_name(err));

        return;
    }

    ESP_LOGI(TAG,
             "NTS status: cert=%d (%u bytes), key=%d (%u bytes), ring=%d",
             status.certificate_present,
             (unsigned int)status.certificate_length,
             status.private_key_present,
             (unsigned int)status.private_key_length,
             status.cookie_ring_present);
}

static void process_line(
    const char *line)
{
    if (strcmp(line,
               "NTS_PROVISION_STATUS") == 0) {
        print_status();
        return;
    }

    if (strcmp(line,
               "NTS_PROVISION_ABORT") == 0) {
        secure_free_buffer();

        ESP_LOGI(TAG,
                 "Provisioning buffer cleared");

        return;
    }

    if (strcmp(line,
               "NTS_PROVISION_CERT_BEGIN") == 0) {
        esp_err_t err = begin_buffer(
            NTS_PROVISION_CERT,
            NTS_PROVISION_CERT_MAX_LEN);

        ESP_LOGI(TAG,
                 "Certificate capture: %s",
                 esp_err_to_name(err));

        return;
    }

    if (strcmp(line,
               "NTS_PROVISION_KEY_BEGIN") == 0) {
        esp_err_t err = begin_buffer(
            NTS_PROVISION_KEY,
            NTS_PROVISION_KEY_MAX_LEN);

        ESP_LOGI(TAG,
                 "Private key capture: %s",
                 esp_err_to_name(err));

        return;
    }

    if (strcmp(line,
               "NTS_PROVISION_CERT_END") == 0) {
        if (s_state != NTS_PROVISION_CERT) {
            ESP_LOGW(TAG,
                     "No active certificate capture");

            return;
        }

        esp_err_t err =
            nts_provisioning_store_certificate(
                s_buffer,
                s_buffer_len);

        secure_free_buffer();

        ESP_LOGI(TAG,
                 "Certificate provisioning: %s",
                 esp_err_to_name(err));

        return;
    }

    if (strcmp(line,
               "NTS_PROVISION_KEY_END") == 0) {
        if (s_state != NTS_PROVISION_KEY) {
            ESP_LOGW(TAG,
                     "No active private key capture");

            return;
        }

        esp_err_t err =
            nts_provisioning_store_private_key(
                s_buffer,
                s_buffer_len);

        secure_free_buffer();

        ESP_LOGI(TAG,
                 "Private-key provisioning: %s",
                 esp_err_to_name(err));

        return;
    }

    if (strcmp(line,
               "NTS_PROVISION_COMMIT") == 0) {
        esp_err_t err =
            nts_provisioning_finalize();

        ESP_LOGI(TAG,
                 "NTS provisioning finalize: %s",
                 esp_err_to_name(err));

        return;
    }

    if (s_state != NTS_PROVISION_IDLE) {
        esp_err_t err = append_line(line);

        if (err != ESP_OK) {
            ESP_LOGE(TAG,
                     "Provisioning input rejected: %s",
                     esp_err_to_name(err));

            secure_free_buffer();
        }

        return;
    }

    ESP_LOGW(TAG,
             "Unknown provisioning command");
}

static void nts_provisioning_uart_task(
    void *arg)
{
    (void)arg;

    char line[NTS_PROVISION_LINE_MAX_LEN];
    size_t line_len = 0U;

    uint8_t rx_buffer[64];

    while (true) {
        int received = uart_read_bytes(
            NTS_PROVISION_UART_NUM,
            rx_buffer,
            sizeof(rx_buffer),
            pdMS_TO_TICKS(250));

        if (received <= 0) {
            continue;
        }

        for (int i = 0; i < received; i++) {
            char value = (char)rx_buffer[i];

            if (value == '\r') {
                continue;
            }

            if (value == '\n') {
                line[line_len] = '\0';

                if (line_len > 0U) {
                    process_line(line);
                }

                line_len = 0U;
                continue;
            }

            if (line_len <
                sizeof(line) - 1U) {
                line[line_len++] = value;
            } else {
                line_len = 0U;

                ESP_LOGW(TAG,
                         "Provisioning line too long");
            }
        }
    }
}

esp_err_t nts_provisioning_uart_start(void)
{
    esp_err_t err = uart_driver_install(
        NTS_PROVISION_UART_NUM,
        NTS_PROVISION_RX_BUFFER_SIZE,
        0U,
        0U,
        NULL,
        0U);

    if (err != ESP_OK &&
        err != ESP_ERR_INVALID_STATE) {
        return err;
    }

    BaseType_t result = xTaskCreate(
        nts_provisioning_uart_task,
        "nts_provision",
        NTS_PROVISION_TASK_STACK_SIZE,
        NULL,
        NTS_PROVISION_TASK_PRIORITY,
        NULL);

    return (result == pdPASS)
        ? ESP_OK
        : ESP_ERR_NO_MEM;
}