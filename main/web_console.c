#include "web_console.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "acme_client.h"
#include "app_state.h"
#include "clock_discipline.h"
#include "cloudflare_client.h"
#include "device_config.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "ntp_server.h"
#include "ntp_types.h"
#include "pps_service.h"

#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "WEB";

#define APP_WEB_CONSOLE_PORT                    443U
#define APP_WEB_CONSOLE_STACK_SIZE              8192U
#define APP_WEB_CONSOLE_MAX_HANDLERS            19U
#define APP_WEB_CONFIG_BODY_MAX                  1024U
#define APP_WEB_CONSOLE_MAX_OPEN_SOCKETS        4U

static httpd_handle_t s_server;
static bool s_started;

extern const unsigned char servercert_pem_start[] asm("_binary_servercert_pem_start");
extern const unsigned char servercert_pem_end[] asm("_binary_servercert_pem_end");
extern const unsigned char management_ca_pem_start[] asm("_binary_management_ca_pem_start");
extern const unsigned char management_ca_pem_end[] asm("_binary_management_ca_pem_end");
extern const unsigned char serverkey_pem_start[] asm("_binary_serverkey_pem_start");
extern const unsigned char serverkey_pem_end[] asm("_binary_serverkey_pem_end");

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
        return "ADD_SECOND";

    case APP_LEAP_DELETE_SECOND:
        return "DELETE_SECOND";

    case APP_LEAP_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static bool clock_is_servable(app_clock_state_t state,
                              bool solution_valid)
{
    return solution_valid &&
           (state == APP_CLOCK_SYNCHRONIZED ||
            state == APP_CLOCK_HOLDOVER);
}

static bool get_current_unix_time(int64_t *out_unix_time)
{
    if (out_unix_time == NULL) {
        return false;
    }

    clock_ntp_timestamp_t ntp_time;

    if (!clock_discipline_get_ntp_timestamp(&ntp_time)) {
        return false;
    }

    if (ntp_time.seconds < APP_NTP_EPOCH_DELTA) {
        return false;
    }

    *out_unix_time =
        (int64_t)ntp_time.seconds -
        (int64_t)APP_NTP_EPOCH_DELTA;

    return true;
}

static void set_security_headers(httpd_req_t *request)
{
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(request, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(request, "Referrer-Policy", "no-referrer");
}

static esp_err_t send_status_json(httpd_req_t *request)
{
    app_state_snapshot_t app_status;
    clock_discipline_status_t clock_status;
    gnss_service_status_t gnss_status;
    pps_service_status_t pps_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;

    (void)app_state_get_snapshot(&app_status);
    (void)clock_discipline_get_status(&clock_status);
    (void)gnss_service_get_status(&gnss_status);
    (void)pps_service_get_status(&pps_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);

    const esp_ip4_addr_t device_ip = {
        .addr = eth_status.ipv4_address,
    };

    const esp_ip4_addr_t netmask = {
        .addr = eth_status.ipv4_netmask,
    };

    const esp_ip4_addr_t gateway = {
        .addr = eth_status.ipv4_gateway,
    };

    const esp_ip4_addr_t last_client = {
        .addr = ntp_status.last_client_ipv4,
    };

    int64_t unix_now = 0;

    const bool current_time_valid =
        get_current_unix_time(&unix_now);

    const bool ntp_ready =
        eth_status.ipv4_ready &&
        ntp_status.socket_bound &&
        clock_is_servable(clock_status.state,
                          clock_status.solution_valid);

    char response[4096];

    const int length = snprintf(
        response,
        sizeof(response),
        "{"
        "\"console\":{"
        "\"mode\":\"mtls_authenticated\","
        "\"port\":%u"
        "},"
        "\"readiness\":{"
        "\"ntp_ready\":%s,"
        "\"clock_now_valid\":%s,"
        "\"unix_time\":%" PRId64
        "},"
        "\"device\":{"
        "\"hostname\":\"%s\","
        "\"ipv4_ready\":%s,"
        "\"ipv4\":\"" IPSTR "\","
        "\"netmask\":\"" IPSTR "\","
        "\"gateway\":\"" IPSTR "\","
        "\"link_up\":%s,"
        "\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\""
        "},"
        "\"clock\":{"
        "\"state\":\"%s\","
        "\"solution_valid\":%s,"
        "\"phase_error_ns\":%" PRId64 ","
        "\"frequency_ppm\":%.6f,"
        "\"accepted_samples\":%" PRIu32 ","
        "\"rejected_samples\":%" PRIu32 ","
        "\"holdover_seconds\":%" PRIu32 ","
        "\"root_dispersion_16_16\":%" PRIu32
        "},"
        "\"gnss\":{"
        "\"utc_valid\":%s,"
        "\"utc_seconds\":%" PRId64 ","
        "\"fix_valid\":%s,"
        "\"fix_type\":%u,"
        "\"satellites\":%u,"
        "\"fully_resolved\":%s,"
        "\"leap\":\"%s\","
        "\"current_leap_seconds\":%d,"
        "\"pending_leap_change\":%d,"
        "\"seconds_to_leap_event\":%" PRId32 ","
        "\"timing_pulse_valid\":%s,"
        "\"timing_week\":%u,"
        "\"timing_tow_ms\":%" PRIu32 ","
        "\"timing_qerr_ps\":%" PRId32
        "},"
        "\"pps\":{"
        "\"valid\":%s,"
        "\"period_us\":%" PRIu32 ","
        "\"jitter_us\":%" PRIu32 ","
        "\"age_us\":%" PRId64 ","
        "\"edge_count\":%" PRIu32 ","
        "\"queue_drops\":%" PRIu32
        "},"
        "\"ntp\":{"
        "\"started\":%s,"
        "\"socket_bound\":%s,"
        "\"requests\":%" PRIu32 ","
        "\"responses\":%" PRIu32 ","
        "\"invalid_requests\":%" PRIu32 ","
        "\"unsynchronized_drops\":%" PRIu32 ","
        "\"rate_kod\":%" PRIu32 ","
        "\"send_failures\":%" PRIu32 ","
        "\"socket_failures\":%" PRIu32 ","
        "\"advertised_stratum\":%u,"
        "\"advertised_leap\":%u,"
        "\"root_dispersion_16_16\":%" PRIu32 ","
        "\"last_client\":\"" IPSTR "\","
        "\"last_request_monotonic_us\":%" PRId64 ","
        "\"last_response_monotonic_us\":%" PRId64
        "}"
        "}",
        APP_WEB_CONSOLE_PORT,
        ntp_ready ? "true" : "false",
        current_time_valid ? "true" : "false",
        unix_now,

        app_status.device_hostname,
        eth_status.ipv4_ready ? "true" : "false",
        IP2STR(&device_ip),
        IP2STR(&netmask),
        IP2STR(&gateway),
        eth_status.link_up ? "true" : "false",
        eth_status.mac[0],
        eth_status.mac[1],
        eth_status.mac[2],
        eth_status.mac[3],
        eth_status.mac[4],
        eth_status.mac[5],

        clock_state_to_string(clock_status.state),
        clock_status.solution_valid ? "true" : "false",
        clock_status.phase_error_ns,
        clock_status.frequency_ppm,
        clock_status.accepted_samples,
        clock_status.rejected_samples,
        clock_status.holdover_seconds,
        clock_status.root_dispersion_16_16,

        gnss_status.utc_valid ? "true" : "false",
        gnss_status.utc_seconds,
        gnss_status.gnss_fix_valid ? "true" : "false",
        gnss_status.fix_type,
        gnss_status.satellites_used,
        gnss_status.gnss_time_fully_resolved ? "true" : "false",
        leap_to_string(gnss_status.leap_indicator),
        gnss_status.current_leap_seconds,
        gnss_status.pending_leap_change,
        gnss_status.seconds_to_leap_event,
        gnss_status.timing_pulse_valid ? "true" : "false",
        gnss_status.timing_week,
        gnss_status.timing_tow_ms,
        gnss_status.timing_quantization_error_ns,

        pps_status.interval_valid ? "true" : "false",
        pps_status.period_us,
        pps_status.jitter_us,
        pps_status.age_us,
        pps_status.edge_count,
        pps_status.queue_drops,

        ntp_status.started ? "true" : "false",
        ntp_status.socket_bound ? "true" : "false",
        ntp_status.requests_received,
        ntp_status.normal_responses,
        ntp_status.invalid_requests,
        ntp_status.unsynchronized_drops,
        ntp_status.rate_kod_responses,
        ntp_status.send_failures,
        ntp_status.socket_open_failures,
        ntp_status.advertised_stratum,
        ntp_status.advertised_leap_indicator,
        ntp_status.advertised_root_dispersion,
        IP2STR(&last_client),
        ntp_status.last_request_monotonic_us,
        ntp_status.last_response_monotonic_us);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "status serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);

    return httpd_resp_send(request,
                           response,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_health_response(httpd_req_t *request)
{
    clock_discipline_status_t clock_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;

    (void)clock_discipline_get_status(&clock_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);

    const bool healthy =
        eth_status.ipv4_ready &&
        eth_status.link_up &&
        ntp_status.socket_bound &&
        clock_is_servable(clock_status.state,
                          clock_status.solution_valid);

    app_state_snapshot_t app_status;
    (void)app_state_get_snapshot(&app_status);

    char response[256];
    const int length = snprintf(
        response,
        sizeof(response),
        "{\"status\":\"%s\",\"hostname\":\"%s\",\"ntp_ready\":%s}\n",
        healthy ? "ok" : "not-ready",
        app_status.device_hostname,
        healthy ? "true" : "false");

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "health serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);

    httpd_resp_set_status(request,
                          healthy ? "200 OK" : "503 Service Unavailable");

    return httpd_resp_send(request,
                           response,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_metrics_response(httpd_req_t *request)
{
    clock_discipline_status_t clock_status;
    gnss_service_status_t gnss_status;
    pps_service_status_t pps_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;

    (void)clock_discipline_get_status(&clock_status);
    (void)gnss_service_get_status(&gnss_status);
    (void)pps_service_get_status(&pps_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);

    char response[3072];

    const int length = snprintf(
        response,
        sizeof(response),
        "# HELP esp32_ntp_clock_state Clock state enumeration.\n"
        "# TYPE esp32_ntp_clock_state gauge\n"
        "esp32_ntp_clock_state %d\n"
        "# HELP esp32_ntp_clock_solution_valid Clock validity.\n"
        "# TYPE esp32_ntp_clock_solution_valid gauge\n"
        "esp32_ntp_clock_solution_valid %d\n"
        "# HELP esp32_ntp_clock_phase_error_ns Clock phase error.\n"
        "# TYPE esp32_ntp_clock_phase_error_ns gauge\n"
        "esp32_ntp_clock_phase_error_ns %" PRId64 "\n"
        "# HELP esp32_ntp_clock_frequency_ppm Clock frequency estimate.\n"
        "# TYPE esp32_ntp_clock_frequency_ppm gauge\n"
        "esp32_ntp_clock_frequency_ppm %.6f\n"
        "# HELP esp32_ntp_clock_holdover_seconds Holdover duration.\n"
        "# TYPE esp32_ntp_clock_holdover_seconds gauge\n"
        "esp32_ntp_clock_holdover_seconds %" PRIu32 "\n"
        "# HELP esp32_ntp_gnss_utc_valid GNSS UTC validity.\n"
        "# TYPE esp32_ntp_gnss_utc_valid gauge\n"
        "esp32_ntp_gnss_utc_valid %d\n"
        "# HELP esp32_ntp_gnss_satellites Satellites used.\n"
        "# TYPE esp32_ntp_gnss_satellites gauge\n"
        "esp32_ntp_gnss_satellites %u\n"
        "# HELP esp32_ntp_pps_valid PPS validity.\n"
        "# TYPE esp32_ntp_pps_valid gauge\n"
        "esp32_ntp_pps_valid %d\n"
        "# HELP esp32_ntp_pps_jitter_us PPS jitter.\n"
        "# TYPE esp32_ntp_pps_jitter_us gauge\n"
        "esp32_ntp_pps_jitter_us %" PRIu32 "\n"
        "# HELP esp32_ntp_ethernet_ipv4_ready Ethernet IPv4 readiness.\n"
        "# TYPE esp32_ntp_ethernet_ipv4_ready gauge\n"
        "esp32_ntp_ethernet_ipv4_ready %d\n"
        "# HELP esp32_ntp_server_socket_bound NTP UDP socket state.\n"
        "# TYPE esp32_ntp_server_socket_bound gauge\n"
        "esp32_ntp_server_socket_bound %d\n"
        "# HELP esp32_ntp_server_requests_total NTP requests.\n"
        "# TYPE esp32_ntp_server_requests_total counter\n"
        "esp32_ntp_server_requests_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_responses_total NTP responses.\n"
        "# TYPE esp32_ntp_server_responses_total counter\n"
        "esp32_ntp_server_responses_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_rate_kod_total RATE KoD responses.\n"
        "# TYPE esp32_ntp_server_rate_kod_total counter\n"
        "esp32_ntp_server_rate_kod_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_unsynchronized_drops_total "
        "Fail-closed NTP drops.\n"
        "# TYPE esp32_ntp_server_unsynchronized_drops_total counter\n"
        "esp32_ntp_server_unsynchronized_drops_total %" PRIu32 "\n",
        (int)clock_status.state,
        clock_status.solution_valid ? 1 : 0,
        clock_status.phase_error_ns,
        clock_status.frequency_ppm,
        clock_status.holdover_seconds,
        gnss_status.utc_valid ? 1 : 0,
        gnss_status.satellites_used,
        pps_status.interval_valid ? 1 : 0,
        pps_status.jitter_us,
        eth_status.ipv4_ready ? 1 : 0,
        ntp_status.socket_bound ? 1 : 0,
        ntp_status.requests_received,
        ntp_status.normal_responses,
        ntp_status.rate_kod_responses,
        ntp_status.unsynchronized_drops);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "metrics serialization failed");
    }

    httpd_resp_set_type(request,
                        "text/plain; version=0.0.4; charset=utf-8");
    set_security_headers(request);

    return httpd_resp_send(request,
                           response,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_config_json(httpd_req_t *request)
{
    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration unavailable");
    }
    char response[768];
    const int length = snprintf(response, sizeof(response),
                                "{\"schema_version\":%" PRIu32
                                ",\"generation\":%" PRIu32
                                ",\"hostname\":\"%s\""
                                ",\"cloudflare\":{\"configured\":%s,"
                                "\"zone_name\":\"%s\",\"zone_id\":\"%s\","
                                "\"api_token_present\":%s}}\n",
                                config.schema_version, config.generation, config.hostname,
                                config.cloudflare_configured ? "true" : "false",
                                config.cloudflare_configured ? config.cloudflare_zone_name : "",
                                config.cloudflare_configured ? config.cloudflare_zone_id : "",
                                config.cloudflare_configured ? "true" : "false");
    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration serialization failed");
    }
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static bool parse_hostname_json(const char *body,
                                char *hostname,
                                size_t hostname_size)
{
    if (body == NULL || hostname == NULL || hostname_size == 0U) {
        return false;
    }

    const char *key = strstr(body, "\"hostname\"");
    if (key == NULL) {
        return false;
    }

    const char *p = key + strlen("\"hostname\"");
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }
    if (*p++ != ':') {
        return false;
    }
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }
    if (*p++ != '"') {
        return false;
    }

    size_t n = 0U;
    while (*p != '\0' && *p != '"') {
        /* Hostnames never require JSON escapes; reject them explicitly. */
        if (*p == '\\' || n + 1U >= hostname_size) {
            return false;
        }
        hostname[n++] = *p++;
    }

    if (*p != '"' || n == 0U) {
        return false;
    }

    hostname[n] = '\0';
    return device_config_hostname_is_valid(hostname);
}

static esp_err_t config_get_handler(httpd_req_t *request)
{
    return send_config_json(request);
}

static esp_err_t hostname_put_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 ||
        request->content_len >= APP_WEB_CONFIG_BODY_MAX) {
        return httpd_resp_send_err(request,
                                   HTTPD_400_BAD_REQUEST,
                                   "invalid request body");
    }

    char body[APP_WEB_CONFIG_BODY_MAX];
    size_t received = 0U;

    while (received < (size_t)request->content_len) {
        const int result = httpd_req_recv(request,
                                          body + received,
                                          (size_t)request->content_len - received);
        if (result == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (result <= 0) {
            return httpd_resp_send_err(request,
                                       HTTPD_400_BAD_REQUEST,
                                       "request body receive failed");
        }
        received += (size_t)result;
    }
    body[received] = '\0';

    char hostname[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];
    if (!parse_hostname_json(body, hostname, sizeof(hostname))) {
        return httpd_resp_send_err(request,
                                   HTTPD_400_BAD_REQUEST,
                                   "expected valid JSON hostname");
    }

    const esp_err_t err = device_config_set_hostname(hostname);
    if (err == ESP_ERR_INVALID_ARG) {
        return httpd_resp_send_err(request,
                                   HTTPD_400_BAD_REQUEST,
                                   "invalid hostname");
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Authenticated hostname update failed: %s",
                 esp_err_to_name(err));
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration commit failed");
    }

    ESP_LOGI(TAG, "Authenticated hostname update accepted");
    return send_config_json(request);
}

static bool extract_json_string(const char *body, const char *name,
                                char *output, size_t output_size)
{
    if (body == NULL || name == NULL || output == NULL || output_size == 0U) return false;
    char key[80];
    const int key_len = snprintf(key, sizeof(key), "\"%s\"", name);
    if (key_len < 0 || key_len >= (int)sizeof(key)) return false;
    const char *p = strstr(body, key);
    if (p == NULL) return false;
    p += strlen(key);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p++ != ':') return false;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p++ != '"') return false;
    size_t n = 0U;
    while (*p != '\0' && *p != '"') {
        if (*p == '\\' || (unsigned char)*p < 0x20U || n + 1U >= output_size) return false;
        output[n++] = *p++;
    }
    if (*p != '"' || n == 0U) return false;
    output[n] = '\0';
    return true;
}

static esp_err_t receive_request_body(httpd_req_t *request, char *body, size_t body_size)
{
    if (request == NULL || body == NULL || body_size < 2U || request->content_len <= 0 ||
        (size_t)request->content_len >= body_size) return ESP_ERR_INVALID_ARG;
    size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int result = httpd_req_recv(request, body + received,
                                          (size_t)request->content_len - received);
        if (result == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (result <= 0) return ESP_FAIL;
        received += (size_t)result;
    }
    body[received] = '\0';
    return ESP_OK;
}

static esp_err_t cloudflare_put_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    }
    char token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
    char zone[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "api_token", token, sizeof(token)) ||
        !extract_json_string(body, "zone_name", zone, sizeof(zone)) ||
        !device_config_cloudflare_zone_is_valid(zone)) {
        memset(token, 0, sizeof(token));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "expected api_token and valid zone_name");
    }
    memset(body, 0, sizeof(body));
    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
    int http_status = 0;
    esp_err_t err = cloudflare_client_resolve_zone(token, zone, zone_id,
                                                   sizeof(zone_id), &http_status);
    if (err != ESP_OK) {
        memset(token, 0, sizeof(token));
        ESP_LOGW(TAG, "Cloudflare credential verification failed: err=%s http=%d",
                 esp_err_to_name(err), http_status);
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "Cloudflare token/zone verification failed");
    }
    err = device_config_set_cloudflare(token, zone, zone_id);
    memset(token, 0, sizeof(token));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cloudflare configuration commit failed: %s", esp_err_to_name(err));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration commit failed");
    }
    return send_config_json(request);
}

static esp_err_t cloudflare_delete_handler(httpd_req_t *request)
{
    const esp_err_t err = device_config_clear_cloudflare();
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration commit failed");
    }
    return send_config_json(request);
}

static esp_err_t cloudflare_verify_handler(httpd_req_t *request)
{
    device_config_cloudflare_credentials_t credentials;
    esp_err_t err = device_config_get_cloudflare_credentials(&credentials);
    if (err == ESP_ERR_NOT_FOUND) {
        return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "Cloudflare is not configured");
    }
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration unavailable");
    }
    char resolved_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
    int http_status = 0;
    err = cloudflare_client_resolve_zone(credentials.api_token, credentials.zone_name,
                                         resolved_id, sizeof(resolved_id), &http_status);
    memset(credentials.api_token, 0, sizeof(credentials.api_token));
    if (err != ESP_OK || strcmp(resolved_id, credentials.zone_id) != 0) {
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request,
                               "Cloudflare verification failed",
                               HTTPD_RESP_USE_STRLEN);
    }
    char response[384];
    const int length = snprintf(response, sizeof(response),
                                "{\"verified\":true,\"zone_name\":\"%s\","
                                "\"zone_id\":\"%s\",\"http_status\":%d}\n",
                                credentials.zone_name, credentials.zone_id, http_status);
    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "serialization failed");
    }
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static bool dns_record_id_is_valid(const char *record_id)
{
    if (record_id == NULL || strlen(record_id) != CLOUDFLARE_DNS_RECORD_ID_LENGTH) return false;
    for (size_t i = 0; i < CLOUDFLARE_DNS_RECORD_ID_LENGTH; ++i) {
        const char c = record_id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}

static esp_err_t build_dns01_name(const char *zone_name, char *output, size_t output_size)
{
    if (zone_name == NULL || output == NULL) return ESP_ERR_INVALID_ARG;
    const int n = snprintf(output, output_size, "_acme-challenge.%s", zone_name);
    return (n < 0 || n >= (int)output_size) ? ESP_ERR_INVALID_SIZE : ESP_OK;
}

static esp_err_t dns01_create_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");

    char value[CLOUDFLARE_DNS01_VALUE_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "value", value, sizeof(value))) {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected DNS-01 value");
    }
    memset(body, 0, sizeof(body));

    device_config_cloudflare_credentials_t credentials;
    esp_err_t err = device_config_get_cloudflare_credentials(&credentials);
    if (err == ESP_ERR_NOT_FOUND) {
        memset(value, 0, sizeof(value));
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK) {
        memset(value, 0, sizeof(value));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    }

    char record_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 32U];
    if (build_dns01_name(credentials.zone_name, record_name, sizeof(record_name)) != ESP_OK) {
        memset(credentials.api_token, 0, sizeof(credentials.api_token));
        memset(value, 0, sizeof(value));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "DNS-01 name too long");
    }

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    int http_status = 0;
    err = cloudflare_client_create_dns01_txt(credentials.api_token, credentials.zone_id,
                                             record_name, value, record_id,
                                             sizeof(record_id), &http_status);
    memset(credentials.api_token, 0, sizeof(credentials.api_token));
    memset(value, 0, sizeof(value));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DNS-01 TXT creation failed: err=%s http=%d", esp_err_to_name(err), http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request, "Cloudflare DNS-01 creation failed", HTTPD_RESP_USE_STRLEN);
    }

    char response[512];
    const int length = snprintf(response, sizeof(response),
                                "{\"created\":true,\"record_name\":\"%s\","
                                "\"record_id\":\"%s\",\"http_status\":%d}\n",
                                record_name, record_id, http_status);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t dns01_query_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    if (!extract_json_string(body, "record_id", record_id, sizeof(record_id)) ||
        !dns_record_id_is_valid(record_id)) {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected valid record_id");
    }
    memset(body, 0, sizeof(body));

    device_config_cloudflare_credentials_t credentials;
    esp_err_t err = device_config_get_cloudflare_credentials(&credentials);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration unavailable");
    }

    char record_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 32U];
    if (build_dns01_name(credentials.zone_name, record_name, sizeof(record_name)) != ESP_OK) {
        memset(credentials.api_token, 0, sizeof(credentials.api_token));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "DNS-01 name too long");
    }

    int http_status = 0;
    err = cloudflare_client_verify_dns01_txt(credentials.api_token, credentials.zone_id,
                                             record_id, record_name, &http_status);
    memset(credentials.api_token, 0, sizeof(credentials.api_token));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DNS-01 TXT query failed: err=%s http=%d",
                 esp_err_to_name(err), http_status);
        httpd_resp_set_status(request, "404 Not Found");
        return httpd_resp_send(request, "Expected Cloudflare DNS-01 record not found",
                               HTTPD_RESP_USE_STRLEN);
    }

    char response[384];
    const int length = snprintf(response, sizeof(response),
                                "{\"verified\":true,\"record_name\":\"%s\"," 
                                "\"record_id\":\"%s\",\"http_status\":%d}\n",
                                record_name, record_id, http_status);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t dns01_delete_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    if (!extract_json_string(body, "record_id", record_id, sizeof(record_id)) ||
        !dns_record_id_is_valid(record_id)) {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected valid record_id");
    }
    memset(body, 0, sizeof(body));

    device_config_cloudflare_credentials_t credentials;
    esp_err_t err = device_config_get_cloudflare_credentials(&credentials);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    }

    char record_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 32U];
    if (build_dns01_name(credentials.zone_name, record_name, sizeof(record_name)) != ESP_OK) {
        memset(credentials.api_token, 0, sizeof(credentials.api_token));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "DNS-01 name too long");
    }

    int http_status = 0;
    err = cloudflare_client_delete_dns01_txt(credentials.api_token, credentials.zone_id,
                                             record_id, record_name, &http_status);
    memset(credentials.api_token, 0, sizeof(credentials.api_token));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DNS-01 TXT deletion failed/refused: err=%s http=%d", esp_err_to_name(err), http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request, "Cloudflare DNS-01 deletion failed", HTTPD_RESP_USE_STRLEN);
    }

    char response[256];
    const int length = snprintf(response, sizeof(response),
                                "{\"deleted\":true,\"record_id\":\"%s\",\"http_status\":%d}\n",
                                record_id, http_status);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}


static esp_err_t acme_account_status_handler(httpd_req_t *request)
{
    acme_account_status_t status;
    const esp_err_t err = acme_client_get_account_status(&status);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ACME account status failed: %s", esp_err_to_name(err));
        httpd_resp_set_status(request, "503 Service Unavailable");
        return httpd_resp_send(request,
                               "ACME account storage unavailable",
                               HTTPD_RESP_USE_STRLEN);
    }

    char response[1100];
    const int length = snprintf(
        response, sizeof(response),
        "{\"environment\":\"staging\",\"key_present\":%s,"
        "\"registered\":%s,\"account_url\":\"%s\","
        "\"jwk_thumbprint\":\"%s\"}\n",
        status.key_present ? "true" : "false",
        status.registered ? "true" : "false",
        status.account_url,
        status.jwk_thumbprint);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME status serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_account_provision_handler(httpd_req_t *request)
{
    acme_account_status_t status;
    const esp_err_t err =
        acme_client_provision_staging_account(&status);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ACME staging account provisioning failed: %s http=%d",
                 esp_err_to_name(err), status.http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request,
                               "Let's Encrypt staging account provisioning failed",
                               HTTPD_RESP_USE_STRLEN);
    }

    char response[1100];
    const int length = snprintf(
        response, sizeof(response),
        "{\"environment\":\"staging\",\"key_present\":%s,"
        "\"registered\":%s,\"http_status\":%d,"
        "\"account_url\":\"%s\",\"jwk_thumbprint\":\"%s\"}\n",
        status.key_present ? "true" : "false",
        status.registered ? "true" : "false",
        status.http_status,
        status.account_url,
        status.jwk_thumbprint);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME account serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_staging_probe_handler(httpd_req_t *request)
{
    acme_directory_status_t status;
    const esp_err_t err = acme_client_probe_staging(&status);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ACME staging probe failed: %s http=%d",
                 esp_err_to_name(err), status.http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request,
                               "Let's Encrypt staging ACME directory probe failed",
                               HTTPD_RESP_USE_STRLEN);
    }

    char response[1400];
    const int length = snprintf(
        response,
        sizeof(response),
        "{\"environment\":\"staging\",\"reachable\":true,"
        "\"http_status\":%d,\"new_nonce\":\"%s\","
        "\"new_account\":\"%s\",\"new_order\":\"%s\"}\n",
        status.http_status,
        status.new_nonce_url,
        status.new_account_url,
        status.new_order_url);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME status serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}


static bool hostname_in_zone(const char *hostname, const char *zone)
{
    if (hostname == NULL || zone == NULL) return false;
    if (strcmp(hostname, zone) == 0) return true;
    const size_t hlen = strlen(hostname);
    const size_t zlen = strlen(zone);
    return hlen > zlen + 1U && hostname[hlen - zlen - 1U] == '.' &&
           strcmp(hostname + hlen - zlen, zone) == 0;
}

static esp_err_t acme_staging_order_discover_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    }
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "hostname", hostname, sizeof(hostname))) {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "expected hostname");
    }
    memset(body, 0, sizeof(body));

    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration unavailable");
    }
    if (!config.cloudflare_configured) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (!hostname_in_zone(hostname, config.cloudflare_zone_name)) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "hostname must be the configured Cloudflare zone or a subdomain");
    }

    acme_order_discovery_t status;
    err = acme_client_discover_staging_order(hostname, &status);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ACME staging order discovery failed: %s newOrder=%d auth=%d",
                 esp_err_to_name(err), status.new_order_http_status,
                 status.authorization_http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request,
                               "Let's Encrypt staging order discovery failed",
                               HTTPD_RESP_USE_STRLEN);
    }

    char *response = calloc(1U, 3072U);
    if (response == NULL) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "out of memory");
    }
    const int length = snprintf(
        response, 3072U,
        "{\"environment\":\"staging\",\"discovered\":true,"
        "\"identifier\":\"%s\",\"new_order_http_status\":%d,"
        "\"authorization_http_status\":%d,\"order_url\":\"%s\","
        "\"authorization_url\":\"%s\",\"finalize_url\":\"%s\","
        "\"challenge\":{\"type\":\"dns-01\",\"status\":\"%s\","
        "\"url\":\"%s\",\"token\":\"%s\"},"
        "\"dns01\":{\"record_name\":\"%s\",\"value\":\"%s\"},"
        "\"challenge_triggered\":false,\"dns_record_created\":false}\n",
        status.identifier, status.new_order_http_status,
        status.authorization_http_status, status.order_url,
        status.authorization_url, status.finalize_url,
        status.challenge_status, status.challenge_url, status.challenge_token,
        status.dns01_record_name, status.dns01_value);
    if (length < 0 || length >= 3072) {
        memset(response, 0, 3072U); free(response);
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME order serialization failed");
    }
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    const esp_err_t send_err = httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    memset(response, 0, 3072U);
    free(response);
    return send_err;
}

static esp_err_t acme_staging_dns01_validate_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    }
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "hostname", hostname, sizeof(hostname))) {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected hostname");
    }
    memset(body, 0, sizeof(body));

    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                   "configuration unavailable");
    if (!config.cloudflare_configured) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (!hostname_in_zone(hostname, config.cloudflare_zone_name)) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "hostname must be the configured Cloudflare zone or a subdomain");
    }

    device_config_cloudflare_credentials_t credentials;
    err = device_config_get_cloudflare_credentials(&credentials);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                   "Cloudflare credentials unavailable");

    acme_order_discovery_t order;
    err = acme_client_discover_staging_order(hostname, &order);
    if (err != ESP_OK) {
        memset(credentials.api_token, 0, sizeof(credentials.api_token));
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request, "ACME order discovery failed", HTTPD_RESP_USE_STRLEN);
    }

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U] = {0};
    int cf_create_status = 0;
    int cf_verify_status = 0;
    int cf_delete_status = 0;
    bool dns_created = false;
    bool dns_content_verified = false;
    bool dns_deleted = false;

    err = cloudflare_client_create_dns01_txt(credentials.api_token, credentials.zone_id,
                                              order.dns01_record_name, order.dns01_value,
                                              record_id, sizeof(record_id), &cf_create_status);
    if (err == ESP_OK) dns_created = true;
    if (err == ESP_OK) {
        err = cloudflare_client_verify_dns01_txt_content(
            credentials.api_token, credentials.zone_id, record_id,
            order.dns01_record_name, order.dns01_value, &cf_verify_status);
        if (err == ESP_OK) dns_content_verified = true;
    }

    acme_challenge_validation_t validation;
    memset(&validation, 0, sizeof(validation));
    esp_err_t validation_err = err;
    if (dns_content_verified) {
        /* Controlled propagation interval before notifying the CA. */
        vTaskDelay(pdMS_TO_TICKS(10000));
        validation_err = acme_client_validate_staging_dns01(&order, &validation);
    }

    /* Cleanup is attempted on success, invalid challenge, timeout, or local error. */
    if (dns_created) {
        const esp_err_t delete_err = cloudflare_client_delete_dns01_txt(
            credentials.api_token, credentials.zone_id, record_id,
            order.dns01_record_name, &cf_delete_status);
        dns_deleted = (delete_err == ESP_OK);
        if (delete_err != ESP_OK) {
            ESP_LOGE(TAG, "ACME DNS-01 cleanup failed: %s http=%d record_id=%s",
                     esp_err_to_name(delete_err), cf_delete_status, record_id);
        }
    }
    memset(credentials.api_token, 0, sizeof(credentials.api_token));

    char *response = calloc(1U, 4096U);
    if (response == NULL) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                      "out of memory");
    const int length = snprintf(
        response, 4096U,
        "{\"environment\":\"staging\",\"identifier\":\"%s\"," 
        "\"order_url\":\"%s\",\"authorization_url\":\"%s\"," 
        "\"challenge_url\":\"%s\"," 
        "\"dns01\":{\"record_name\":\"%s\",\"value\":\"%s\"," 
        "\"record_id\":\"%s\",\"created\":%s,\"content_verified\":%s," 
        "\"create_http_status\":%d,\"verify_http_status\":%d,\"deleted\":%s," 
        "\"delete_http_status\":%d}," 
        "\"challenge\":{\"triggered\":%s,\"valid\":%s," 
        "\"trigger_http_status\":%d,\"poll_http_status\":%d,\"poll_count\":%u," 
        "\"authorization_status\":\"%s\",\"status\":\"%s\"}}\n",
        order.identifier, order.order_url, order.authorization_url, order.challenge_url,
        order.dns01_record_name, order.dns01_value, record_id,
        dns_created ? "true" : "false", dns_content_verified ? "true" : "false",
        cf_create_status, cf_verify_status, dns_deleted ? "true" : "false", cf_delete_status,
        validation.triggered ? "true" : "false", validation.valid ? "true" : "false",
        validation.trigger_http_status, validation.poll_http_status, validation.poll_count,
        validation.authorization_status, validation.challenge_status);
    if (length < 0 || length >= 4096) {
        memset(response, 0, 4096U); free(response);
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME validation serialization failed");
    }
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    if (validation_err != ESP_OK || !validation.valid || !dns_deleted) {
        httpd_resp_set_status(request, "502 Bad Gateway");
    }
    const esp_err_t send_err = httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    memset(response, 0, 4096U); free(response);
    return send_err;
}


static esp_err_t acme_staging_certificate_issue_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "hostname", hostname, sizeof(hostname))) {
        memset(body,0,sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected hostname");
    }
    memset(body,0,sizeof(body));

    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    if (!config.cloudflare_configured) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (!hostname_in_zone(hostname, config.cloudflare_zone_name))
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "hostname must be the configured Cloudflare zone or a subdomain");

    device_config_cloudflare_credentials_t credentials;
    err = device_config_get_cloudflare_credentials(&credentials);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                   "Cloudflare credentials unavailable");

    acme_order_discovery_t order;
    err = acme_client_discover_staging_order(hostname, &order);
    if (err != ESP_OK) {
        memset(credentials.api_token,0,sizeof(credentials.api_token));
        httpd_resp_set_status(request,"502 Bad Gateway");
        return httpd_resp_send(request,"ACME order discovery failed",HTTPD_RESP_USE_STRLEN);
    }

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U] = {0};
    int cf_create_status=0, cf_verify_status=0, cf_delete_status=0;
    bool dns_created=false, dns_verified=false, dns_deleted=false;
    err = cloudflare_client_create_dns01_txt(credentials.api_token, credentials.zone_id,
                                              order.dns01_record_name, order.dns01_value,
                                              record_id, sizeof(record_id), &cf_create_status);
    if (err == ESP_OK) dns_created=true;
    if (err == ESP_OK) {
        err = cloudflare_client_verify_dns01_txt_content(credentials.api_token, credentials.zone_id,
                                                          record_id, order.dns01_record_name,
                                                          order.dns01_value, &cf_verify_status);
        if (err == ESP_OK) dns_verified=true;
    }

    acme_challenge_validation_t validation; memset(&validation,0,sizeof(validation));
    esp_err_t validation_err=err;
    if (dns_verified) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        validation_err=acme_client_validate_staging_dns01(&order,&validation);
    }

    if (dns_created) {
        const esp_err_t delete_err=cloudflare_client_delete_dns01_txt(credentials.api_token,
            credentials.zone_id, record_id, order.dns01_record_name, &cf_delete_status);
        dns_deleted=(delete_err==ESP_OK);
        if (delete_err != ESP_OK) ESP_LOGE(TAG,"ACME DNS-01 cleanup failed: %s http=%d record_id=%s",
                                           esp_err_to_name(delete_err),cf_delete_status,record_id);
    }
    memset(credentials.api_token,0,sizeof(credentials.api_token));

    acme_certificate_issue_status_t certificate; memset(&certificate,0,sizeof(certificate));
    esp_err_t certificate_err = validation_err;
    if (validation_err == ESP_OK && validation.valid && dns_deleted)
        certificate_err = acme_client_finalize_staging_order(&order, &certificate);

    char *response=calloc(1U,4096U);
    if (response==NULL) return httpd_resp_send_err(request,HTTPD_500_INTERNAL_SERVER_ERROR,"out of memory");
    const int length=snprintf(response,4096U,
        "{\"environment\":\"staging\",\"identifier\":\"%s\"," 
        "\"order_url\":\"%s\"," 
        "\"dns01\":{\"record_name\":\"%s\",\"record_id\":\"%s\","
        "\"created\":%s,\"content_verified\":%s,\"deleted\":%s,"
        "\"create_http_status\":%d,\"verify_http_status\":%d,\"delete_http_status\":%d},"
        "\"challenge\":{\"valid\":%s,\"authorization_status\":\"%s\"},"
        "\"certificate\":{\"finalized\":%s,\"retrieved\":%s,\"stored\":%s,"
        "\"finalize_http_status\":%d,\"order_poll_http_status\":%d,\"order_poll_count\":%u,"
        "\"order_status\":\"%s\",\"certificate_http_status\":%d,"
        "\"certificate_url\":\"%s\",\"pem_length\":%u},"
        "\"active_management_tls_changed\":false}\n",
        order.identifier,order.order_url,order.dns01_record_name,record_id,
        dns_created?"true":"false",dns_verified?"true":"false",dns_deleted?"true":"false",
        cf_create_status,cf_verify_status,cf_delete_status,
        validation.valid?"true":"false",validation.authorization_status,
        certificate.finalized?"true":"false",certificate.certificate_retrieved?"true":"false",
        certificate.stored?"true":"false",certificate.finalize_http_status,
        certificate.order_poll_http_status,certificate.order_poll_count,certificate.order_status,
        certificate.certificate_http_status,certificate.certificate_url,
        (unsigned)certificate.certificate_pem_length);
    if (length<0 || length>=4096) { memset(response,0,4096U); free(response); return httpd_resp_send_err(request,HTTPD_500_INTERNAL_SERVER_ERROR,"ACME certificate serialization failed"); }
    httpd_resp_set_type(request,"application/json"); set_security_headers(request);
    if (certificate_err != ESP_OK || !certificate.stored) httpd_resp_set_status(request,"502 Bad Gateway");
    const esp_err_t send_err=httpd_resp_send(request,response,HTTPD_RESP_USE_STRLEN);
    memset(response,0,4096U); free(response); return send_err;
}



static esp_err_t acme_certificate_inspection_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t status;
    const esp_err_t err = acme_client_inspect_stored_certificate(&status);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "404 Not Found");
        return httpd_resp_send(request, "No stored ACME certificate", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Stored certificate inspection failed: %s", esp_err_to_name(err));
        httpd_resp_set_status(request, "500 Internal Server Error");
        return httpd_resp_send(request, "Stored certificate inspection failed", HTTPD_RESP_USE_STRLEN);
    }

    char response[1024];
    const int length = snprintf(response, sizeof(response),
        "{\"stored\":true,\"hostname\":\"%s\"," 
        "\"key_present\":%s,\"certificate_present\":%s,\"hostname_present\":%s,"
        "\"certificate_parse_valid\":%s,\"hostname_matches_certificate\":%s,"
        "\"private_key_matches_certificate\":%s,\"chain_certificate_count\":%u,"
        "\"pem_length\":%u,\"valid_from\":\"%s\",\"valid_to\":\"%s\","
        "\"leaf_sha256\":\"%s\",\"active_management_tls_changed\":false}\n",
        status.hostname,
        status.key_present ? "true" : "false",
        status.certificate_present ? "true" : "false",
        status.hostname_present ? "true" : "false",
        status.certificate_parse_valid ? "true" : "false",
        status.hostname_matches_certificate ? "true" : "false",
        status.private_key_matches_certificate ? "true" : "false",
        status.chain_certificate_count,
        (unsigned)status.certificate_pem_length,
        status.valid_from, status.valid_to, status.leaf_sha256);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    if (err == ESP_ERR_INVALID_STATE) httpd_resp_set_status(request, "409 Conflict");
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t index_handler(httpd_req_t *request)
{
    static const char html[] =
        "<!doctype html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>ESP32-P4 NTP Console</title>"
        "<style>"
        ":root{color-scheme:dark}"
        "body{margin:0;background:#0d141b;color:#e9f0f5;"
        "font-family:Arial,sans-serif}"
        "header{padding:22px 28px;background:#14212d;border-bottom:1px solid #294252}"
        "h1{margin:0;color:#58c7ff;font-size:1.55rem}"
        "header p{margin:7px 0 0;color:#a8bac7;font-size:.92rem}"
        "main{padding:22px;max-width:1320px;margin:auto}"
        ".summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}"
        ".badge{padding:8px 12px;border-radius:999px;font-weight:bold;font-size:.82rem}"
        ".ok{background:#173f2b;color:#9bea75}"
        ".warn{background:#493b18;color:#ffd569}"
        ".bad{background:#4c2226;color:#ff9292}"
        ".neutral{background:#223643;color:#a9d8ef}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}"
        ".card{background:#14212d;border:1px solid #294252;border-radius:10px;"
        "padding:18px;min-width:0}"
        ".card h2{margin:0 0 14px;color:#8fdb75;font-size:1.02rem}"
        ".row{display:grid;grid-template-columns:minmax(135px,1fr) minmax(145px,auto);"
        "column-gap:30px;row-gap:7px;padding:10px 0;"
        "border-bottom:1px solid #203440;align-items:center}"
        ".row:last-child{border-bottom:0}"
        ".key{color:#9eb2c0;line-height:1.4}"
        ".value{font-family:ui-monospace,Consolas,monospace;text-align:right;"
        "line-height:1.4;overflow-wrap:anywhere}"
        "footer{padding:22px 0 4px;color:#8ca1ae;font-size:.82rem}"
        "code{color:#9bea75}"
        "</style>"
        "</head>"
        "<body>"
        "<header>"
        "<h1>ESP32-P4 GNSS NTP Server</h1>"
        "<p>mTLS-authenticated HTTPS operational console &middot; automatic refresh every three seconds</p>"
        "</header>"
        "<main>"
        "<div class=\"summary\" id=\"summary\"></div>"
        "<div class=\"grid\" id=\"cards\"></div>"
        "<footer>"
        "mTLS management endpoints: <code>/api/v1/status</code> &middot; "
        "<code>/api/v1/health</code> &middot; <code>/metrics</code> &middot; "
        "<code>GET /api/v1/config</code> &middot; <code>PUT /api/v1/config/hostname</code> &middot; <code>PUT/DELETE /api/v1/config/cloudflare</code>"
        "</footer>"
        "</main>"
        "<script>"
        "function esc(v){return String(v == null ? '--' : v).replace(/[&<>\"']/g,"
        "c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}"
        "function row(k,v){return '<div class=\"row\"><span class=\"key\">'+esc(k)+"
        "'</span><span class=\"value\">'+esc(v)+'</span></div>';}"
        "function card(t,r){return '<section class=\"card\"><h2>'+esc(t)+"
        "'</h2>'+r.join('')+'</section>';}"
        "function badge(t,c){return '<span class=\"badge '+c+'\">'+esc(t)+'</span>';}"
        "function stateClass(s){if(s==='SYNCHRONIZED')return 'ok';"
        "if(s==='HOLDOVER'||s==='ACQUIRING')return 'warn';return 'bad';}"
        "function yesNo(v){return v?'YES':'NO';}"
        "function utc(v,valid){if(!valid)return '--';"
        "return new Date(Number(v)*1000).toISOString();}"
        "async function refresh(){"
        "try{"
        "const r=await fetch('/api/v1/status',{cache:'no-store'});"
        "if(!r.ok)throw new Error('status unavailable');"
        "const d=await r.json();"
        "const summary=[];"
        "summary.push(badge('Clock: '+d.clock.state,stateClass(d.clock.state)));"
        "summary.push(badge('NTP: '+(d.readiness.ntp_ready?'READY':'NOT READY'),"
        "d.readiness.ntp_ready?'ok':'bad'));"
        "summary.push(badge('GNSS UTC: '+yesNo(d.gnss.utc_valid),"
        "d.gnss.utc_valid?'ok':'bad'));"
        "summary.push(badge('PPS: '+yesNo(d.pps.valid),"
        "d.pps.valid?'ok':'bad'));"
        "summary.push(badge('Ethernet: '+yesNo(d.device.ipv4_ready),"
        "d.device.ipv4_ready?'ok':'bad'));"
        "document.getElementById('summary').innerHTML=summary.join('');"
        "const c=[];"
        "c.push(card('Clock and Time',["
        "row('State',d.clock.state),"
        "row('Disciplined',yesNo(d.clock.solution_valid)),"
        "row('UTC Time',utc(d.readiness.unix_time,d.readiness.clock_now_valid)),"
        "row('Phase Error',d.clock.phase_error_ns+' ns'),"
        "row('Frequency',d.clock.frequency_ppm+' ppm'),"
        "row('Samples',d.clock.accepted_samples+' accepted / '+d.clock.rejected_samples+' rejected'),"
        "row('Holdover',d.clock.holdover_seconds+' s'),"
        "row('Root Dispersion','0x'+Number(d.clock.root_dispersion_16_16).toString(16))"
        "]));"
        "c.push(card('GNSS Receiver',["
        "row('UTC Valid',yesNo(d.gnss.utc_valid)),"
        "row('Fix Valid',yesNo(d.gnss.fix_valid)),"
        "row('Fix Type',d.gnss.fix_type),"
        "row('Satellites',d.gnss.satellites),"
        "row('Time Fully Resolved',yesNo(d.gnss.fully_resolved)),"
        "row('Leap State',d.gnss.leap),"
        "row('Current Leap Offset',d.gnss.current_leap_seconds+' s'),"
        "row('TIM-TP qErr',d.gnss.timing_qerr_ps+' ps')"
        "]));"
        "c.push(card('PPS Capture',["
        "row('Interval Valid',yesNo(d.pps.valid)),"
        "row('Period',d.pps.period_us+' us'),"
        "row('Jitter',d.pps.jitter_us+' us'),"
        "row('Last Edge Age',d.pps.age_us+' us'),"
        "row('Captured Edges',d.pps.edge_count),"
        "row('Queue Drops',d.pps.queue_drops)"
        "]));"
        "c.push(card('Network',["
        "row('Hostname',d.device.hostname),"
        "row('IPv4 Address',d.device.ipv4),"
        "row('Netmask',d.device.netmask),"
        "row('Gateway',d.device.gateway),"
        "row('Ethernet Link',yesNo(d.device.link_up)),"
        "row('Ethernet MAC',d.device.mac),"
        "row('Console Mode',d.console.mode)"
        "]));"
        "c.push(card('NTP Service',["
        "row('UDP Socket Bound',yesNo(d.ntp.socket_bound)),"
        "row('Advertised Stratum',d.ntp.advertised_stratum),"
        "row('Requests Received',d.ntp.requests),"
        "row('Responses Sent',d.ntp.responses),"
        "row('Invalid Requests',d.ntp.invalid_requests),"
        "row('Fail-Closed Drops',d.ntp.unsynchronized_drops),"
        "row('RATE KoD Responses',d.ntp.rate_kod),"
        "row('Last Client',d.ntp.last_client)"
        "]));"
        "document.getElementById('cards').innerHTML=c.join('');"
        "}catch(e){"
        "document.getElementById('summary').innerHTML=badge('Console: STATUS UNAVAILABLE','bad');"
        "document.getElementById('cards').innerHTML="
        "'<section class=\"card\"><h2>Console Error</h2><p>Unable to retrieve device status.</p></section>';"
        "}"
        "}"
        "refresh();setInterval(refresh,3000);"
        "</script>"
        "</body>"
        "</html>";

    httpd_resp_set_type(request, "text/html");
    set_security_headers(request);

    return httpd_resp_send(request,
                           html,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t status_handler(httpd_req_t *request)
{
    return send_status_json(request);
}

static esp_err_t health_handler(httpd_req_t *request)
{
    return send_health_response(request);
}

static esp_err_t metrics_handler(httpd_req_t *request)
{
    return send_metrics_response(request);
}

static const httpd_uri_t s_index_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = index_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_status_uri = {
    .uri = "/api/v1/status",
    .method = HTTP_GET,
    .handler = status_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_health_uri = {
    .uri = "/api/v1/health",
    .method = HTTP_GET,
    .handler = health_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_metrics_uri = {
    .uri = "/metrics",
    .method = HTTP_GET,
    .handler = metrics_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_config_get_uri = {
    .uri = "/api/v1/config",
    .method = HTTP_GET,
    .handler = config_get_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_hostname_put_uri = {
    .uri = "/api/v1/config/hostname",
    .method = HTTP_PUT,
    .handler = hostname_put_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_cloudflare_put_uri = {
    .uri = "/api/v1/config/cloudflare", .method = HTTP_PUT,
    .handler = cloudflare_put_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_cloudflare_delete_uri = {
    .uri = "/api/v1/config/cloudflare", .method = HTTP_DELETE,
    .handler = cloudflare_delete_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_cloudflare_verify_uri = {
    .uri = "/api/v1/config/cloudflare/verify", .method = HTTP_POST,
    .handler = cloudflare_verify_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_dns01_create_uri = {
    .uri = "/api/v1/cloudflare/dns01", .method = HTTP_POST,
    .handler = dns01_create_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_dns01_query_uri = {
    .uri = "/api/v1/cloudflare/dns01/query", .method = HTTP_POST,
    .handler = dns01_query_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_dns01_delete_uri = {
    .uri = "/api/v1/cloudflare/dns01", .method = HTTP_DELETE,
    .handler = dns01_delete_handler, .user_ctx = NULL,
};


static const httpd_uri_t s_acme_account_status_uri = {
    .uri = "/api/v1/acme/account",
    .method = HTTP_GET,
    .handler = acme_account_status_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_account_provision_uri = {
    .uri = "/api/v1/acme/account",
    .method = HTTP_POST,
    .handler = acme_account_provision_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_staging_probe_uri = {
    .uri = "/api/v1/acme/staging/probe",
    .method = HTTP_POST,
    .handler = acme_staging_probe_handler,
    .user_ctx = NULL,
};


static const httpd_uri_t s_acme_staging_order_discover_uri = {
    .uri = "/api/v1/acme/staging/order/discover",
    .method = HTTP_POST,
    .handler = acme_staging_order_discover_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_staging_dns01_validate_uri = {
    .uri = "/api/v1/acme/staging/dns01/validate",
    .method = HTTP_POST,
    .handler = acme_staging_dns01_validate_handler,
    .user_ctx = NULL,
};


static const httpd_uri_t s_acme_staging_certificate_issue_uri = {
    .uri = "/api/v1/acme/staging/certificate/issue",
    .method = HTTP_POST,
    .handler = acme_staging_certificate_issue_handler,
    .user_ctx = NULL,
};



static const httpd_uri_t s_acme_certificate_inspection_uri = {
    .uri = "/api/v1/acme/certificate",
    .method = HTTP_GET,
    .handler = acme_certificate_inspection_handler,
    .user_ctx = NULL,
};

esp_err_t web_console_start(void)
{
    if (s_started) {
        return ESP_OK;
    }

    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();

    config.httpd.stack_size = APP_WEB_CONSOLE_STACK_SIZE;
    config.httpd.max_uri_handlers = APP_WEB_CONSOLE_MAX_HANDLERS;
    config.httpd.max_open_sockets = APP_WEB_CONSOLE_MAX_OPEN_SOCKETS;
    config.httpd.lru_purge_enable = true;
    config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    config.port_secure = APP_WEB_CONSOLE_PORT;
    config.servercert = servercert_pem_start;
    config.servercert_len = (size_t)(servercert_pem_end - servercert_pem_start);
    config.prvtkey_pem = serverkey_pem_start;
    config.prvtkey_len = (size_t)(serverkey_pem_end - serverkey_pem_start);
    config.cacert_pem = management_ca_pem_start;
    config.cacert_len = (size_t)(management_ca_pem_end - management_ca_pem_start);

    esp_err_t err = httpd_ssl_start(&s_server, &config);

    if (err != ESP_OK) {
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_index_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_status_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_health_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_metrics_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_config_get_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_hostname_put_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_cloudflare_put_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_cloudflare_delete_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_cloudflare_verify_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_dns01_create_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_dns01_query_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_dns01_delete_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_acme_staging_probe_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_acme_account_status_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_acme_account_provision_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_acme_staging_order_discover_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_acme_staging_dns01_validate_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_acme_staging_certificate_issue_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }
    err = httpd_register_uri_handler(s_server, &s_acme_certificate_inspection_uri);
    if (err != ESP_OK) { (void)httpd_ssl_stop(s_server); s_server = NULL; return err; }

    s_started = true;

    ESP_LOGW(TAG,
             "mTLS management console active on TCP/%u; "
             "client certificate required",
             APP_WEB_CONSOLE_PORT);

    return ESP_OK;
}

bool web_console_is_running(void)
{
    return s_started;
}