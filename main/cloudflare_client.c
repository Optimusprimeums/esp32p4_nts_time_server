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
                                 "https://api.cloudflare.com/client/v4/zones?name=%s&status=active&per_page=5",
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


static bool extract_dns_record_id(const char *json, char *record_id, size_t record_id_size)
{
    if (json == NULL || record_id == NULL ||
        record_id_size < CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U) {
        return false;
    }

    const char *result = strstr(json, "\"result\"");
    if (result == NULL) return false;
    const char *object = strchr(result, '{');
    if (object == NULL) return false;
    const char *id = strstr(object, "\"id\"");
    if (id == NULL) return false;
    const char *colon = strchr(id, ':');
    if (colon == NULL) return false;
    const char *p = skip_ws(colon + 1);
    if (p == NULL || *p++ != '"') return false;

    for (size_t i = 0; i < CLOUDFLARE_DNS_RECORD_ID_LENGTH; ++i) {
        if (!isxdigit((unsigned char)p[i])) return false;
        record_id[i] = p[i];
    }
    if (p[CLOUDFLARE_DNS_RECORD_ID_LENGTH] != '"') return false;
    record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH] = '\0';
    return true;
}

static bool is_hex_id(const char *value, size_t length)
{
    if (value == NULL || strlen(value) != length) return false;
    for (size_t i = 0; i < length; ++i) {
        if (!isxdigit((unsigned char)value[i])) return false;
    }
    return true;
}

static bool dns01_value_is_valid(const char *value)
{
    if (value == NULL) return false;
    const size_t length = strlen(value);
    if (length == 0U || length > CLOUDFLARE_DNS01_VALUE_MAX_LENGTH) return false;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char ch = (unsigned char)value[i];
        if (!(isalnum(ch) || ch == '-' || ch == '_')) return false;
    }
    return true;
}

static bool json_string_equals(const char *json, const char *key, const char *expected)
{
    if (json == NULL || key == NULL || expected == NULL) return false;
    char needle[64];
    const int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n < 0 || n >= (int)sizeof(needle)) return false;
    const char *p = strstr(json, needle);
    if (p == NULL) return false;
    p = strchr(p + strlen(needle), ':');
    if (p == NULL) return false;
    p = skip_ws(p + 1);
    if (p == NULL || *p++ != '"') return false;
    const size_t expected_len = strlen(expected);
    return strncmp(p, expected, expected_len) == 0 && p[expected_len] == '"';
}

static esp_err_t cloudflare_http_request(const char *api_token,
                                         esp_http_client_method_t method,
                                         const char *url,
                                         const char *json_body,
                                         response_buffer_t *response,
                                         int *out_http_status)
{
    if (api_token == NULL || url == NULL || response == NULL) return ESP_ERR_INVALID_ARG;
    memset(response, 0, sizeof(*response));
    if (out_http_status != NULL) *out_http_status = 0;

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = http_event_handler,
        .user_data = response,
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

    esp_err_t err = esp_http_client_set_method(client, method);
    if (err == ESP_OK) err = esp_http_client_set_header(client, "Authorization", authorization);
    if (err == ESP_OK) err = esp_http_client_set_header(client, "Accept", "application/json");
    if (err == ESP_OK) err = esp_http_client_set_header(client, "User-Agent", "esp32p4-ntp/phase5b7");
    if (err == ESP_OK && json_body != NULL) {
        err = esp_http_client_set_header(client, "Content-Type", "application/json");
        if (err == ESP_OK) {
            err = esp_http_client_set_post_field(client, json_body, (int)strlen(json_body));
        }
    }
    if (err == ESP_OK) err = esp_http_client_perform(client);

    const int status = esp_http_client_get_status_code(client);
    if (out_http_status != NULL) *out_http_status = status;
    memset(authorization, 0, sizeof(authorization));
    esp_http_client_cleanup(client);

    if (err != ESP_OK) return err;
    if (response->overflow) return ESP_ERR_INVALID_SIZE;
    return ESP_OK;
}

static esp_err_t cloudflare_create_dns01_txt_sync(const char *api_token,
                                                   const char *zone_id,
                                                   const char *record_name,
                                                   const char *txt_value,
                                                   char *record_id,
                                                   size_t record_id_size,
                                                   int *out_http_status)
{
    if (api_token == NULL || !is_hex_id(zone_id, APP_CLOUDFLARE_ZONE_ID_LENGTH) ||
        record_name == NULL || !dns01_value_is_valid(txt_value) || record_id == NULL ||
        record_id_size < CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U) return ESP_ERR_INVALID_ARG;
    record_id[0] = '\0';

    char url[CF_URL_MAX];
    if (snprintf(url, sizeof(url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records", zone_id) >= (int)sizeof(url))
        return ESP_ERR_INVALID_SIZE;

    char body[768];
    const int body_len = snprintf(body, sizeof(body),
        "{\"type\":\"TXT\",\"name\":\"%s\",\"content\":\"\\\"%s\\\"\",\"ttl\":1,\"comment\":\"ESP32-P4 ACME DNS-01\"}",
        record_name, txt_value);
    if (body_len < 0 || body_len >= (int)sizeof(body)) return ESP_ERR_INVALID_SIZE;

    response_buffer_t response;
    int status = 0;
    esp_err_t err = cloudflare_http_request(api_token, HTTP_METHOD_POST, url, body, &response, &status);
    memset(body, 0, sizeof(body));
    if (out_http_status != NULL) *out_http_status = status;
    if (err != ESP_OK) return err;
    if (status != 200) return ESP_ERR_INVALID_RESPONSE;
    if (!response_success(response.data) ||
        !extract_dns_record_id(response.data, record_id, record_id_size))
        return ESP_ERR_INVALID_RESPONSE;
    return ESP_OK;
}

static esp_err_t cloudflare_verify_dns01_txt_sync(const char *api_token,
                                                   const char *zone_id,
                                                   const char *record_id,
                                                   const char *expected_record_name,
                                                   int *out_http_status)
{
    if (api_token == NULL || !is_hex_id(zone_id, APP_CLOUDFLARE_ZONE_ID_LENGTH) ||
        !is_hex_id(record_id, CLOUDFLARE_DNS_RECORD_ID_LENGTH) || expected_record_name == NULL)
        return ESP_ERR_INVALID_ARG;

    char url[CF_URL_MAX];
    if (snprintf(url, sizeof(url),
                 "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
                 zone_id, record_id) >= (int)sizeof(url))
        return ESP_ERR_INVALID_SIZE;

    response_buffer_t response;
    int status = 0;
    esp_err_t err = cloudflare_http_request(api_token, HTTP_METHOD_GET, url, NULL,
                                             &response, &status);
    if (out_http_status != NULL) *out_http_status = status;
    if (err != ESP_OK) return err;
    if (status != 200 || !response_success(response.data)) return ESP_ERR_NOT_FOUND;
    if (!json_string_equals(response.data, "type", "TXT") ||
        !json_string_equals(response.data, "name", expected_record_name))
        return ESP_ERR_INVALID_STATE;
    return ESP_OK;
}

static bool json_txt_content_equals(const char *json, const char *expected)
{
    if (json == NULL || expected == NULL) return false;
    const char *p = strstr(json, "\"content\"");
    if (p == NULL) return false;
    p = strchr(p, ':');
    if (p == NULL) return false;
    p = skip_ws(p + 1);
    if (p == NULL || *p++ != '"') return false;

    char decoded[CLOUDFLARE_DNS01_VALUE_MAX_LENGTH + 3U];
    size_t used = 0U;
    while (*p != '\0' && *p != '"' && used + 1U < sizeof(decoded)) {
        if (*p == '\\') {
            ++p;
            if (*p != '"' && *p != '\\') return false;
        }
        decoded[used++] = *p++;
    }
    if (*p != '"') return false;
    decoded[used] = '\0';

    const size_t len = strlen(decoded);
    if (len >= 2U && decoded[0] == '"' && decoded[len - 1U] == '"') {
        decoded[len - 1U] = '\0';
        return strcmp(decoded + 1U, expected) == 0;
    }
    return strcmp(decoded, expected) == 0;
}

static esp_err_t cloudflare_verify_dns01_txt_content_sync(const char *api_token,
                                                           const char *zone_id,
                                                           const char *record_id,
                                                           const char *expected_record_name,
                                                           const char *expected_txt_value,
                                                           int *out_http_status)
{
    if (api_token == NULL || !is_hex_id(zone_id, APP_CLOUDFLARE_ZONE_ID_LENGTH) ||
        !is_hex_id(record_id, CLOUDFLARE_DNS_RECORD_ID_LENGTH) ||
        expected_record_name == NULL || !dns01_value_is_valid(expected_txt_value))
        return ESP_ERR_INVALID_ARG;
    char url[CF_URL_MAX];
    if (snprintf(url, sizeof(url),
                 "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
                 zone_id, record_id) >= (int)sizeof(url)) return ESP_ERR_INVALID_SIZE;
    response_buffer_t response;
    int status = 0;
    esp_err_t err = cloudflare_http_request(api_token, HTTP_METHOD_GET, url, NULL,
                                             &response, &status);
    if (out_http_status != NULL) *out_http_status = status;
    if (err != ESP_OK) return err;
    if (status != 200 || !response_success(response.data)) return ESP_ERR_NOT_FOUND;
    if (!json_string_equals(response.data, "type", "TXT") ||
        !json_string_equals(response.data, "name", expected_record_name) ||
        !json_txt_content_equals(response.data, expected_txt_value))
        return ESP_ERR_INVALID_STATE;
    return ESP_OK;
}

static esp_err_t cloudflare_delete_dns01_txt_sync(const char *api_token,
                                                   const char *zone_id,
                                                   const char *record_id,
                                                   const char *expected_record_name,
                                                   int *out_http_status)
{
    if (api_token == NULL || !is_hex_id(zone_id, APP_CLOUDFLARE_ZONE_ID_LENGTH) ||
        !is_hex_id(record_id, CLOUDFLARE_DNS_RECORD_ID_LENGTH) || expected_record_name == NULL)
        return ESP_ERR_INVALID_ARG;

    char url[CF_URL_MAX];
    if (snprintf(url, sizeof(url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zone_id, record_id) >= (int)sizeof(url))
        return ESP_ERR_INVALID_SIZE;

    response_buffer_t response;
    int status = 0;
    esp_err_t err = cloudflare_verify_dns01_txt_sync(api_token, zone_id, record_id,
                                                      expected_record_name, &status);
    if (out_http_status != NULL) *out_http_status = status;
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Refusing to delete DNS record that is not the expected DNS-01 TXT record");
        return err;
    }

    err = cloudflare_http_request(api_token, HTTP_METHOD_DELETE, url, NULL, &response, &status);
    if (out_http_status != NULL) *out_http_status = status;
    if (err != ESP_OK) return err;
    if (status != 200 || !response_success(response.data)) return ESP_ERR_INVALID_RESPONSE;
    return ESP_OK;
}

#define CF_WORKER_STACK_SIZE 16384U
#define CF_WORKER_PRIORITY   5U

typedef enum {
    CF_WORK_RESOLVE_ZONE = 0,
    CF_WORK_CREATE_DNS01,
    CF_WORK_VERIFY_DNS01,
    CF_WORK_VERIFY_DNS01_CONTENT,
    CF_WORK_DELETE_DNS01,
} cloudflare_work_type_t;

typedef struct {
    TaskHandle_t caller;
    cloudflare_work_type_t type;
    char api_token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
    char zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
    char record_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 32U];
    char txt_value[CLOUDFLARE_DNS01_VALUE_MAX_LENGTH + 1U];
    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    int http_status;
    esp_err_t result;
} cloudflare_worker_context_t;

static void cloudflare_worker(void *argument)
{
    cloudflare_worker_context_t *context = (cloudflare_worker_context_t *)argument;
    switch (context->type) {
    case CF_WORK_RESOLVE_ZONE:
        context->result = cloudflare_client_resolve_zone_sync(
            context->api_token, context->zone_name, context->zone_id,
            sizeof(context->zone_id), &context->http_status);
        break;
    case CF_WORK_CREATE_DNS01:
        context->result = cloudflare_create_dns01_txt_sync(
            context->api_token, context->zone_id, context->record_name,
            context->txt_value, context->record_id, sizeof(context->record_id),
            &context->http_status);
        break;
    case CF_WORK_VERIFY_DNS01:
        context->result = cloudflare_verify_dns01_txt_sync(
            context->api_token, context->zone_id, context->record_id,
            context->record_name, &context->http_status);
        break;
    case CF_WORK_VERIFY_DNS01_CONTENT:
        context->result = cloudflare_verify_dns01_txt_content_sync(
            context->api_token, context->zone_id, context->record_id,
            context->record_name, context->txt_value, &context->http_status);
        break;
    case CF_WORK_DELETE_DNS01:
        context->result = cloudflare_delete_dns01_txt_sync(
            context->api_token, context->zone_id, context->record_id,
            context->record_name, &context->http_status);
        break;
    default:
        context->result = ESP_ERR_INVALID_ARG;
        break;
    }
    memset(context->api_token, 0, sizeof(context->api_token));
    memset(context->txt_value, 0, sizeof(context->txt_value));
    xTaskNotifyGive(context->caller);
    vTaskDelete(NULL);
}

static esp_err_t run_worker(cloudflare_worker_context_t *context)
{
    context->caller = xTaskGetCurrentTaskHandle();
    BaseType_t created = xTaskCreate(cloudflare_worker, "cf_api", CF_WORKER_STACK_SIZE,
                                     context, CF_WORKER_PRIORITY, NULL);
    if (created != pdPASS) return ESP_ERR_NO_MEM;
    (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    return context->result;
}

esp_err_t cloudflare_client_resolve_zone(const char *api_token,
                                         const char *zone_name,
                                         char *zone_id,
                                         size_t zone_id_size,
                                         int *out_http_status)
{
    if (api_token == NULL || zone_name == NULL || zone_id == NULL ||
        zone_id_size < APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U) return ESP_ERR_INVALID_ARG;
    zone_id[0] = '\0';
    if (out_http_status != NULL) *out_http_status = 0;

    cloudflare_worker_context_t *ctx = calloc(1U, sizeof(*ctx));
    if (ctx == NULL) return ESP_ERR_NO_MEM;
    ctx->type = CF_WORK_RESOLVE_ZONE;
    if (snprintf(ctx->api_token, sizeof(ctx->api_token), "%s", api_token) >= (int)sizeof(ctx->api_token) ||
        snprintf(ctx->zone_name, sizeof(ctx->zone_name), "%s", zone_name) >= (int)sizeof(ctx->zone_name)) {
        memset(ctx, 0, sizeof(*ctx)); free(ctx); return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t result = run_worker(ctx);
    if (out_http_status != NULL) *out_http_status = ctx->http_status;
    if (result == ESP_OK) memcpy(zone_id, ctx->zone_id, APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U);
    memset(ctx, 0, sizeof(*ctx)); free(ctx);
    return result;
}

esp_err_t cloudflare_client_create_dns01_txt(const char *api_token,
                                             const char *zone_id,
                                             const char *record_name,
                                             const char *txt_value,
                                             char *record_id,
                                             size_t record_id_size,
                                             int *out_http_status)
{
    if (api_token == NULL || zone_id == NULL || record_name == NULL || txt_value == NULL ||
        record_id == NULL || record_id_size < CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U)
        return ESP_ERR_INVALID_ARG;
    record_id[0] = '\0';
    if (out_http_status != NULL) *out_http_status = 0;

    cloudflare_worker_context_t *ctx = calloc(1U, sizeof(*ctx));
    if (ctx == NULL) return ESP_ERR_NO_MEM;
    ctx->type = CF_WORK_CREATE_DNS01;
    if (snprintf(ctx->api_token, sizeof(ctx->api_token), "%s", api_token) >= (int)sizeof(ctx->api_token) ||
        snprintf(ctx->zone_id, sizeof(ctx->zone_id), "%s", zone_id) >= (int)sizeof(ctx->zone_id) ||
        snprintf(ctx->record_name, sizeof(ctx->record_name), "%s", record_name) >= (int)sizeof(ctx->record_name) ||
        snprintf(ctx->txt_value, sizeof(ctx->txt_value), "%s", txt_value) >= (int)sizeof(ctx->txt_value)) {
        memset(ctx, 0, sizeof(*ctx)); free(ctx); return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t result = run_worker(ctx);
    if (out_http_status != NULL) *out_http_status = ctx->http_status;
    if (result == ESP_OK) memcpy(record_id, ctx->record_id, CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U);
    memset(ctx, 0, sizeof(*ctx)); free(ctx);
    return result;
}

esp_err_t cloudflare_client_verify_dns01_txt(const char *api_token,
                                             const char *zone_id,
                                             const char *record_id,
                                             const char *expected_record_name,
                                             int *out_http_status)
{
    if (api_token == NULL || zone_id == NULL || record_id == NULL || expected_record_name == NULL)
        return ESP_ERR_INVALID_ARG;
    if (out_http_status != NULL) *out_http_status = 0;

    cloudflare_worker_context_t *ctx = calloc(1U, sizeof(*ctx));
    if (ctx == NULL) return ESP_ERR_NO_MEM;
    ctx->type = CF_WORK_VERIFY_DNS01;
    if (snprintf(ctx->api_token, sizeof(ctx->api_token), "%s", api_token) >= (int)sizeof(ctx->api_token) ||
        snprintf(ctx->zone_id, sizeof(ctx->zone_id), "%s", zone_id) >= (int)sizeof(ctx->zone_id) ||
        snprintf(ctx->record_id, sizeof(ctx->record_id), "%s", record_id) >= (int)sizeof(ctx->record_id) ||
        snprintf(ctx->record_name, sizeof(ctx->record_name), "%s", expected_record_name) >= (int)sizeof(ctx->record_name)) {
        memset(ctx, 0, sizeof(*ctx)); free(ctx); return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t result = run_worker(ctx);
    if (out_http_status != NULL) *out_http_status = ctx->http_status;
    memset(ctx, 0, sizeof(*ctx)); free(ctx);
    return result;
}

esp_err_t cloudflare_client_verify_dns01_txt_content(const char *api_token,
                                                     const char *zone_id,
                                                     const char *record_id,
                                                     const char *expected_record_name,
                                                     const char *expected_txt_value,
                                                     int *out_http_status)
{
    if (api_token == NULL || zone_id == NULL || record_id == NULL ||
        expected_record_name == NULL || expected_txt_value == NULL) return ESP_ERR_INVALID_ARG;
    if (out_http_status != NULL) *out_http_status = 0;
    cloudflare_worker_context_t *ctx = calloc(1U, sizeof(*ctx));
    if (ctx == NULL) return ESP_ERR_NO_MEM;
    ctx->type = CF_WORK_VERIFY_DNS01_CONTENT;
    if (snprintf(ctx->api_token, sizeof(ctx->api_token), "%s", api_token) >= (int)sizeof(ctx->api_token) ||
        snprintf(ctx->zone_id, sizeof(ctx->zone_id), "%s", zone_id) >= (int)sizeof(ctx->zone_id) ||
        snprintf(ctx->record_id, sizeof(ctx->record_id), "%s", record_id) >= (int)sizeof(ctx->record_id) ||
        snprintf(ctx->record_name, sizeof(ctx->record_name), "%s", expected_record_name) >= (int)sizeof(ctx->record_name) ||
        snprintf(ctx->txt_value, sizeof(ctx->txt_value), "%s", expected_txt_value) >= (int)sizeof(ctx->txt_value)) {
        memset(ctx, 0, sizeof(*ctx)); free(ctx); return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t result = run_worker(ctx);
    if (out_http_status != NULL) *out_http_status = ctx->http_status;
    memset(ctx, 0, sizeof(*ctx)); free(ctx);
    return result;
}

esp_err_t cloudflare_client_delete_dns01_txt(const char *api_token,
                                             const char *zone_id,
                                             const char *record_id,
                                             const char *expected_record_name,
                                             int *out_http_status)
{
    if (api_token == NULL || zone_id == NULL || record_id == NULL || expected_record_name == NULL)
        return ESP_ERR_INVALID_ARG;
    if (out_http_status != NULL) *out_http_status = 0;

    cloudflare_worker_context_t *ctx = calloc(1U, sizeof(*ctx));
    if (ctx == NULL) return ESP_ERR_NO_MEM;
    ctx->type = CF_WORK_DELETE_DNS01;
    if (snprintf(ctx->api_token, sizeof(ctx->api_token), "%s", api_token) >= (int)sizeof(ctx->api_token) ||
        snprintf(ctx->zone_id, sizeof(ctx->zone_id), "%s", zone_id) >= (int)sizeof(ctx->zone_id) ||
        snprintf(ctx->record_id, sizeof(ctx->record_id), "%s", record_id) >= (int)sizeof(ctx->record_id) ||
        snprintf(ctx->record_name, sizeof(ctx->record_name), "%s", expected_record_name) >= (int)sizeof(ctx->record_name)) {
        memset(ctx, 0, sizeof(*ctx)); free(ctx); return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t result = run_worker(ctx);
    if (out_http_status != NULL) *out_http_status = ctx->http_status;
    memset(ctx, 0, sizeof(*ctx)); free(ctx);
    return result;
}