#include "cloudflare_client.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_config.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "CLOUDFLARE";
#define CF_RESPONSE_MAX 4096U
#define CF_URL_MAX      384U
#define CF_AUTH_MAX     (APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 16U)

typedef struct {
    char data[CF_RESPONSE_MAX];
    size_t used;
    bool overflow;
} response_buffer_t;

static esp_err_t http_event_handler(esp_http_client_event_t *event)
{
    if (event == NULL || event->user_data == NULL) return ESP_OK;
    response_buffer_t *response = (response_buffer_t *)event->user_data;
    if (event->event_id == HTTP_EVENT_ON_DATA && event->data != NULL && event->data_len > 0) {
        const size_t incoming = (size_t)event->data_len;
        if (incoming > sizeof(response->data) - 1U - response->used) {
            response->overflow = true;
            return ESP_OK;
        }
        memcpy(response->data + response->used, event->data, incoming);
        response->used += incoming;
        response->data[response->used] = '\0';
    }
    return ESP_OK;
}

static const char *skip_ws(const char *p)
{
    while (p != NULL && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
    return p;
}

static bool response_success(const char *json)
{
    const char *p = strstr(json, "\"success\"");
    if (p == NULL) return false;
    p = strchr(p, ':');
    if (p == NULL) return false;
    p = skip_ws(p + 1);
    return p != NULL && strncmp(p, "true", 4U) == 0;
}

static bool extract_zone_id(const char *json, char *zone_id, size_t zone_id_size)
{
    if (zone_id_size < APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U) return false;
    const char *result = strstr(json, "\"result\"");
    if (result == NULL) return false;
    const char *array = strchr(result, '[');
    if (array == NULL) return false;
    const char *object = strchr(array, '{');
    if (object == NULL) return false;
    const char *id = strstr(object, "\"id\"");
    if (id == NULL) return false;
    const char *colon = strchr(id, ':');
    if (colon == NULL) return false;
    const char *p = skip_ws(colon + 1);
    if (p == NULL || *p++ != '"') return false;
    for (size_t i = 0; i < APP_CLOUDFLARE_ZONE_ID_LENGTH; ++i) {
        if (!isxdigit((unsigned char)p[i])) return false;
        zone_id[i] = p[i];
    }
    if (p[APP_CLOUDFLARE_ZONE_ID_LENGTH] != '"') return false;
    zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH] = '\0';
    return true;
}

static esp_err_t cloudflare_client_resolve_zone_sync(const char *api_token,
                                         const char *zone_name,
                                         char *zone_id,
                                         size_t zone_id_size,
                                         int *out_http_status)
{
    if (api_token == NULL || zone_name == NULL || zone_id == NULL ||
        zone_id_size < APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U) return ESP_ERR_INVALID_ARG;
    zone_id[0] = '\0';
    if (out_http_status != NULL) *out_http_status = 0;

    char url[CF_URL_MAX];
    const int url_len = snprintf(url, sizeof(url),
                                 "https://api.cloudflare.com/client/v4/zones?name=%s&status=active&per_page=1",
                                 zone_name);
    if (url_len < 0 || url_len >= (int)sizeof(url)) return ESP_ERR_INVALID_SIZE;

    response_buffer_t response = {0};
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = http_event_handler,
        .user_data = &response,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 10000,
        .keep_alive_enable = false,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) return ESP_ERR_NO_MEM;

    char authorization[CF_AUTH_MAX];
    const int auth_len = snprintf(authorization, sizeof(authorization), "Bearer %s", api_token);
    if (auth_len < 0 || auth_len >= (int)sizeof(authorization)) {
        esp_http_client_cleanup(client);
        return ESP_ERR_INVALID_SIZE;
    }

    (void)esp_http_client_set_header(client, "Authorization", authorization);
    (void)esp_http_client_set_header(client, "Accept", "application/json");
    (void)esp_http_client_set_header(client, "User-Agent", "esp32p4-ntp/phase5b6");

    esp_err_t err = esp_http_client_perform(client);
    const int status = esp_http_client_get_status_code(client);
    if (out_http_status != NULL) *out_http_status = status;
    memset(authorization, 0, sizeof(authorization));
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Cloudflare HTTPS request failed: %s", esp_err_to_name(err));
        return err;
    }
    if (response.overflow) {
        ESP_LOGW(TAG, "Cloudflare response exceeded local buffer");
        return ESP_ERR_INVALID_SIZE;
    }
    if (status != 200) {
        ESP_LOGW(TAG, "Cloudflare API returned HTTP %d", status);
        return ESP_ERR_INVALID_RESPONSE;
    }
    if (!response_success(response.data) ||
        !extract_zone_id(response.data, zone_id, zone_id_size)) {
        ESP_LOGW(TAG, "Cloudflare token/zone verification did not return a zone");
        return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG, "Cloudflare zone verified: %s", zone_name);
    return ESP_OK;
}

#define CF_WORKER_STACK_SIZE 16384U
#define CF_WORKER_PRIORITY   5U

typedef struct {
    TaskHandle_t caller;
    char api_token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
    char zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
    int http_status;
    esp_err_t result;
} cloudflare_worker_context_t;

static void cloudflare_resolve_zone_worker(void *argument)
{
    cloudflare_worker_context_t *context =
        (cloudflare_worker_context_t *)argument;

    context->result = cloudflare_client_resolve_zone_sync(
        context->api_token,
        context->zone_name,
        context->zone_id,
        sizeof(context->zone_id),
        &context->http_status);

    memset(context->api_token, 0, sizeof(context->api_token));

    /*
     * The caller owns the context and remains blocked until this notification.
     * Notify only after all worker writes to the shared context are complete.
     */
    xTaskNotifyGive(context->caller);
    vTaskDelete(NULL);
}

esp_err_t cloudflare_client_resolve_zone(const char *api_token,
                                         const char *zone_name,
                                         char *zone_id,
                                         size_t zone_id_size,
                                         int *out_http_status)
{
    if (api_token == NULL || zone_name == NULL || zone_id == NULL ||
        zone_id_size < APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U) {
        return ESP_ERR_INVALID_ARG;
    }

    zone_id[0] = '\0';
    if (out_http_status != NULL) {
        *out_http_status = 0;
    }

    cloudflare_worker_context_t *context =
        (cloudflare_worker_context_t *)calloc(1U, sizeof(*context));
    if (context == NULL) {
        return ESP_ERR_NO_MEM;
    }

    context->caller = xTaskGetCurrentTaskHandle();

    const int token_len = snprintf(context->api_token,
                                   sizeof(context->api_token),
                                   "%s",
                                   api_token);
    const int zone_len = snprintf(context->zone_name,
                                  sizeof(context->zone_name),
                                  "%s",
                                  zone_name);

    if (token_len < 0 ||
        token_len >= (int)sizeof(context->api_token) ||
        zone_len < 0 ||
        zone_len >= (int)sizeof(context->zone_name)) {
        memset(context, 0, sizeof(*context));
        free(context);
        return ESP_ERR_INVALID_SIZE;
    }

    /*
     * Use a dedicated task so outbound Cloudflare HTTP/TLS processing does not
     * consume the HTTPS server task's stack. The request remains synchronous
     * from the API client's perspective.
     */
    BaseType_t created = xTaskCreate(
        cloudflare_resolve_zone_worker,
        "cf_api",
        CF_WORKER_STACK_SIZE,
        context,
        CF_WORKER_PRIORITY,
        NULL);

    if (created != pdPASS) {
        memset(context, 0, sizeof(*context));
        free(context);
        return ESP_ERR_NO_MEM;
    }

    (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

    const esp_err_t result = context->result;
    if (out_http_status != NULL) {
        *out_http_status = context->http_status;
    }

    if (result == ESP_OK) {
        memcpy(zone_id,
               context->zone_id,
               APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U);
    }

    memset(context, 0, sizeof(*context));
    free(context);
    return result;
}

