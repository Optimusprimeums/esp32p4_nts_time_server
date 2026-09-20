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
#include "nts_ke.h"
#include "nts_ntp_auth.h"
#include "pps_service.h"

#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "WEB";

#define APP_WEB_CONSOLE_PORT                    443U
#define APP_WEB_CONSOLE_STACK_SIZE              8192U
#define APP_WEB_CONSOLE_MAX_HANDLERS            36U
#define APP_WEB_CONFIG_BODY_MAX                  1024U
#define APP_WEB_CONSOLE_MAX_OPEN_SOCKETS        4U
#define APP_ACME_RENEWAL_CHECK_INTERVAL_MS       (6U * 60U * 60U * 1000U)
#define APP_ACME_RENEWAL_INITIAL_DELAY_MS         30000U
#define APP_ACME_RENEWAL_TASK_STACK_SIZE          8192U
#define APP_ACME_RENEWAL_TASK_PRIORITY               4U
#define APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION      1U
#define APP_TLS_ACTIVATION_OUTCOME_KEY                 "tls_out"
#define APP_TLS_HANDOFF_RECORD_VERSION                  1U
#define APP_TLS_HANDOFF_KEY                             "tls_hnd"
#define APP_TLS_HANDOFF_RETRY_SECONDS                   (6LL * 60LL * 60LL)
#define APP_ACME_RENEWAL_ATTEMPT_COOLDOWN_SECONDS   (6LL * 60LL * 60LL)

static httpd_handle_t s_server;
static bool s_started;

typedef enum {
    WEB_TLS_EMBEDDED = 0,
    WEB_TLS_STORED_TEST,
    WEB_TLS_PRODUCTION,
} web_tls_source_t;

static volatile bool s_tls_transition_pending;
static volatile bool s_tls_transition_automatic;
static portMUX_TYPE s_tls_transition_lock = portMUX_INITIALIZER_UNLOCKED;
static web_tls_source_t s_tls_source = WEB_TLS_EMBEDDED;
static acme_tls_credentials_t s_active_stored_credentials;
static char s_active_server_leaf_sha256[65];

typedef struct {
    uint32_t version;
    bool result_valid;
    bool success;
    bool lkg_restored;
    int64_t completed_unix;
    esp_err_t transition_result;
    char target_leaf_sha256[65];
    char running_leaf_sha256[65];
} tls_activation_outcome_record_t;

typedef struct {
    uint32_t version;
    bool in_progress;
    bool recovered_interrupted;
    uint32_t attempt_count;
    int64_t started_unix;
    int64_t retry_not_before_unix;
    char target_leaf_sha256[65];
} tls_handoff_record_t;

typedef enum {
    ACME_RENEWAL_SCHEDULER_NOT_EVALUATED = 0,
    ACME_RENEWAL_SCHEDULER_NO_CERTIFICATE,
    ACME_RENEWAL_SCHEDULER_TIME_UNAVAILABLE,
    ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE,
    ACME_RENEWAL_SCHEDULER_VALID,
    ACME_RENEWAL_SCHEDULER_DUE,
    ACME_RENEWAL_SCHEDULER_URGENT,
    ACME_RENEWAL_SCHEDULER_EXPIRED,
} acme_renewal_scheduler_state_t;

typedef struct {
    bool task_started;
    bool evaluated;
    uint32_t evaluation_count;
    int64_t last_evaluation_unix;
    int64_t seconds_remaining;
    int64_t days_remaining;
    acme_renewal_scheduler_state_t state;
    bool automatic_renewal_enabled;
    bool eligible;
    bool execution_preflight_ready;
    bool attempt_in_progress;
    uint32_t attempt_count;
    int64_t last_attempt_unix;
    int64_t retry_not_before_unix;
    bool last_attempt_result_valid;
    esp_err_t last_attempt_result;
    acme_production_transaction_stage_t last_transaction_stage;
    bool last_transaction_completed;
    bool last_dns01_prepared;
    bool last_cleanup_attempted;
    esp_err_t last_cleanup_result;
    bool attempt_state_loaded;
    bool recovered_interrupted_attempt;
    bool tls_activation_preflight_evaluated;
    bool tls_activation_preflight_ready;
    bool tls_candidate_valid;
    bool tls_candidate_hostname_match;
    bool tls_candidate_time_valid;
    bool tls_candidate_fingerprint_changed;
    bool tls_activation_in_progress;
    char tls_candidate_leaf_sha256[65];
    char tls_current_leaf_sha256[65];
    char tls_activation_preflight_result[40];
    bool tls_activation_intent_state_loaded;
    bool tls_activation_intent_pending;
    bool tls_activation_boot_reconciled;
    int64_t tls_activation_intent_created_unix;
    char tls_activation_intent_previous_leaf_sha256[65];
    char tls_activation_intent_target_leaf_sha256[65];
    char tls_activation_reconciliation_result[40];
    bool tls_activation_outcome_state_loaded;
    bool tls_activation_last_result_valid;
    bool tls_activation_last_success;
    bool tls_activation_last_lkg_restored;
    int64_t tls_activation_last_completed_unix;
    esp_err_t tls_activation_last_transition_result;
    char tls_activation_last_target_leaf_sha256[65];
    char tls_activation_last_running_leaf_sha256[65];
    bool tls_handoff_state_loaded;
    bool tls_handoff_in_progress;
    bool tls_handoff_recovered_interrupted;
    uint32_t tls_handoff_attempt_count;
    int64_t tls_handoff_started_unix;
    int64_t tls_handoff_retry_not_before_unix;
    char tls_handoff_target_leaf_sha256[65];
} acme_renewal_scheduler_status_t;

static portMUX_TYPE s_renewal_scheduler_lock = portMUX_INITIALIZER_UNLOCKED;
static acme_renewal_scheduler_status_t s_renewal_scheduler_status;
static TaskHandle_t s_renewal_scheduler_task;

static esp_err_t start_https_server(web_tls_source_t source);
static esp_err_t start_https_server_with_credentials(web_tls_source_t source,
                                                     acme_tls_credentials_t *credentials,
                                                     const char *known_leaf_sha256);
static bool tls_transition_try_claim(void);
static void tls_transition_release(void);
static void tls_transition_task(void *arg);
static bool hostname_in_zone(const char *hostname, const char *zone);
static esp_err_t tls_activation_intent_load_and_reconcile(void);
static esp_err_t tls_activation_intent_begin(const char *previous_leaf_sha256, int64_t now);
static esp_err_t tls_activation_intent_set_target(const char *target_leaf_sha256);
static esp_err_t tls_activation_intent_clear(bool boot_reconciled);
static esp_err_t tls_activation_schedule_pending_target(void);
static esp_err_t receive_request_body(httpd_req_t *request, char *body, size_t body_size);
static esp_err_t tls_activation_outcome_load(void);
static esp_err_t tls_activation_outcome_store(bool success, bool lkg_restored, esp_err_t transition_result,
                                              const char *target_leaf_sha256,
                                              const char *running_leaf_sha256);
static esp_err_t tls_handoff_load_and_reconcile(void);
static esp_err_t tls_handoff_begin(const char *target_leaf_sha256, int64_t now);
static esp_err_t tls_handoff_finish(bool success, int64_t now);

static const char *tls_source_name(web_tls_source_t source)
{
    switch (source) {
    case WEB_TLS_STORED_TEST: return "stored_staging_test";
    case WEB_TLS_PRODUCTION: return "stored_production";
    default: return "embedded_development";
    }
}

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

static bool parse_utc_timestamp(const char *text, int64_t *out_unix)
{
    if (text == NULL || out_unix == NULL) return false;
    int y, mo, d, h, mi, sec;
    char tail = '\0';
    if (sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2dZ%c", &y, &mo, &d, &h, &mi, &sec, &tail) != 6)
        return false;
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 ||
        mi < 0 || mi > 59 || sec < 0 || sec > 60) return false;

    /* Howard Hinnant's civil-date transform, adapted to integer UTC seconds. */
    y -= mo <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned mp = (unsigned)(mo + (mo > 2 ? -3 : 9));
    const unsigned doy = (153U * mp + 2U) / 5U + (unsigned)d - 1U;
    const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    const int64_t days = (int64_t)era * 146097LL + (int64_t)doe - 719468LL;
    *out_unix = days * 86400LL + (int64_t)h * 3600LL + (int64_t)mi * 60LL + sec;
    return true;
}

static void evaluate_tls_activation_preflight(acme_renewal_scheduler_status_t *status,
                                              const acme_certificate_inspection_t *certificate)
{
    if (status == NULL) return;

    status->tls_activation_preflight_evaluated = true;
    status->tls_activation_in_progress = s_tls_transition_pending;
    snprintf(status->tls_activation_preflight_result,
             sizeof(status->tls_activation_preflight_result), "not_ready");

    if (certificate == NULL || !certificate->certificate_parse_valid ||
        !certificate->private_key_matches_certificate) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "invalid_candidate");
        return;
    }

    status->tls_candidate_valid = true;
    status->tls_candidate_hostname_match = certificate->hostname_matches_certificate;
    snprintf(status->tls_candidate_leaf_sha256, sizeof(status->tls_candidate_leaf_sha256),
             "%s", certificate->leaf_sha256);
    snprintf(status->tls_current_leaf_sha256, sizeof(status->tls_current_leaf_sha256),
             "%s", s_active_server_leaf_sha256);

    int64_t now = 0, valid_from = 0, valid_to = 0;
    status->tls_candidate_time_valid =
        get_current_unix_time(&now) &&
        parse_utc_timestamp(certificate->valid_from, &valid_from) &&
        parse_utc_timestamp(certificate->valid_to, &valid_to) &&
        now >= valid_from && now < valid_to;

    status->tls_candidate_fingerprint_changed =
        s_active_server_leaf_sha256[0] != '\0' &&
        certificate->leaf_sha256[0] != '\0' &&
        strcmp(s_active_server_leaf_sha256, certificate->leaf_sha256) != 0;

    if (!status->tls_candidate_hostname_match) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "hostname_mismatch");
    } else if (!status->tls_candidate_time_valid) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "time_invalid");
    } else if (s_active_server_leaf_sha256[0] == '\0') {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "current_fingerprint_unavailable");
    } else if (!status->tls_candidate_fingerprint_changed) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "candidate_not_changed");
    } else if (status->tls_activation_in_progress) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "activation_in_progress");
    } else {
        status->tls_activation_preflight_ready = true;
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "ready");
    }
}

static const char *renewal_scheduler_state_name(acme_renewal_scheduler_state_t state)
{
    switch (state) {
    case ACME_RENEWAL_SCHEDULER_NO_CERTIFICATE: return "no_certificate";
    case ACME_RENEWAL_SCHEDULER_TIME_UNAVAILABLE: return "time_unavailable";
    case ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE: return "invalid_certificate";
    case ACME_RENEWAL_SCHEDULER_VALID: return "valid";
    case ACME_RENEWAL_SCHEDULER_DUE: return "renewal_due";
    case ACME_RENEWAL_SCHEDULER_URGENT: return "urgent";
    case ACME_RENEWAL_SCHEDULER_EXPIRED: return "expired";
    default: return "not_evaluated";
    }
}


static const char *renewal_transaction_stage_to_string(acme_production_transaction_stage_t stage)
{
    switch (stage) {
        case ACME_PRODUCTION_TRANSACTION_STAGE_NONE: return "none";
        case ACME_PRODUCTION_TRANSACTION_STAGE_ACCOUNT: return "account";
        case ACME_PRODUCTION_TRANSACTION_STAGE_ORDER: return "order";
        case ACME_PRODUCTION_TRANSACTION_STAGE_DNS01_PREPARE: return "dns01_prepare";
        case ACME_PRODUCTION_TRANSACTION_STAGE_CHALLENGE: return "challenge";
        case ACME_PRODUCTION_TRANSACTION_STAGE_FINALIZE: return "finalize";
        case ACME_PRODUCTION_TRANSACTION_STAGE_DNS01_CLEANUP: return "dns01_cleanup";
        case ACME_PRODUCTION_TRANSACTION_STAGE_COMPLETE: return "complete";
        default: return "unknown";
    }
}

typedef struct {
    device_config_cloudflare_credentials_t credentials;
    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    bool record_created;
} renewal_dns01_context_t;

static esp_err_t renewal_dns01_prepare(const acme_order_discovery_t *order, void *context)
{
    if (order == NULL || context == NULL) return ESP_ERR_INVALID_ARG;
    renewal_dns01_context_t *dns = (renewal_dns01_context_t *)context;
    int create_http_status = 0;
    int verify_http_status = 0;

    esp_err_t err = cloudflare_client_create_dns01_txt(
        dns->credentials.api_token, dns->credentials.zone_id,
        order->dns01_record_name, order->dns01_value,
        dns->record_id, sizeof(dns->record_id), &create_http_status);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal DNS-01 create failed: %s http=%d",
                 esp_err_to_name(err), create_http_status);
        return err;
    }
    dns->record_created = true;

    err = cloudflare_client_verify_dns01_txt_content(
        dns->credentials.api_token, dns->credentials.zone_id,
        dns->record_id, order->dns01_record_name, order->dns01_value,
        &verify_http_status);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal DNS-01 exact-content verify failed: %s http=%d",
                 esp_err_to_name(err), verify_http_status);

        /* The transaction core only invokes cleanup after a successful prepare.
         * Therefore a partial prepare must remove its own record before failing. */
        int delete_http_status = 0;
        const esp_err_t delete_err = cloudflare_client_delete_dns01_txt_content(
            dns->credentials.api_token, dns->credentials.zone_id,
            dns->record_id, order->dns01_record_name, order->dns01_value, &delete_http_status);
        if (delete_err == ESP_OK) {
            dns->record_created = false;
            memset(dns->record_id, 0, sizeof(dns->record_id));
        } else {
            ESP_LOGE(TAG, "Automatic renewal partial DNS-01 cleanup failed: %s http=%d",
                     esp_err_to_name(delete_err), delete_http_status);
        }
        return err;
    }

    /* Preserve the already-validated Phase 5B DNS-01 propagation delay. */
    vTaskDelay(pdMS_TO_TICKS(10000));
    return ESP_OK;
}

static esp_err_t renewal_dns01_cleanup(const acme_order_discovery_t *order, void *context)
{
    if (order == NULL || context == NULL) return ESP_ERR_INVALID_ARG;
    renewal_dns01_context_t *dns = (renewal_dns01_context_t *)context;
    if (!dns->record_created) return ESP_OK;

    int delete_http_status = 0;
    const esp_err_t err = cloudflare_client_delete_dns01_txt_content(
        dns->credentials.api_token, dns->credentials.zone_id,
        dns->record_id, order->dns01_record_name, order->dns01_value, &delete_http_status);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal DNS-01 cleanup failed: %s http=%d",
                 esp_err_to_name(err), delete_http_status);
        return err;
    }

    dns->record_created = false;
    memset(dns->record_id, 0, sizeof(dns->record_id));
    return ESP_OK;
}

static esp_err_t renewal_scheduler_persist_attempt_state(bool attempt_was_in_progress)
{
    acme_renewal_attempt_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = ACME_RENEWAL_ATTEMPT_RECORD_VERSION;
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    record.attempt_count = s_renewal_scheduler_status.attempt_count;
    record.last_attempt_unix = s_renewal_scheduler_status.last_attempt_unix;
    record.retry_not_before_unix = s_renewal_scheduler_status.retry_not_before_unix;
    record.attempt_was_in_progress = attempt_was_in_progress;
    record.last_attempt_result_valid = s_renewal_scheduler_status.last_attempt_result_valid;
    record.last_attempt_result = s_renewal_scheduler_status.last_attempt_result;
    record.last_transaction_stage = s_renewal_scheduler_status.last_transaction_stage;
    record.last_transaction_completed = s_renewal_scheduler_status.last_transaction_completed;
    record.last_dns01_prepared = s_renewal_scheduler_status.last_dns01_prepared;
    record.last_cleanup_attempted = s_renewal_scheduler_status.last_cleanup_attempted;
    record.last_cleanup_result = s_renewal_scheduler_status.last_cleanup_result;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    return acme_client_store_renewal_attempt_record(&record);
}

static esp_err_t renewal_scheduler_load_attempt_state(void)
{
    acme_renewal_attempt_record_t record;
    const esp_err_t err = acme_client_load_renewal_attempt_record(&record);
    if (err != ESP_OK) return err;
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.attempt_count = record.attempt_count;
    s_renewal_scheduler_status.last_attempt_unix = record.last_attempt_unix;
    s_renewal_scheduler_status.retry_not_before_unix = record.retry_not_before_unix;
    s_renewal_scheduler_status.last_attempt_result_valid = record.last_attempt_result_valid;
    s_renewal_scheduler_status.last_attempt_result = record.last_attempt_result;
    s_renewal_scheduler_status.last_transaction_stage = record.last_transaction_stage;
    s_renewal_scheduler_status.last_transaction_completed = record.last_transaction_completed;
    s_renewal_scheduler_status.last_dns01_prepared = record.last_dns01_prepared;
    s_renewal_scheduler_status.last_cleanup_attempted = record.last_cleanup_attempted;
    s_renewal_scheduler_status.last_cleanup_result = record.last_cleanup_result;
    s_renewal_scheduler_status.attempt_in_progress = false;
    s_renewal_scheduler_status.attempt_state_loaded = true;
    s_renewal_scheduler_status.recovered_interrupted_attempt = record.attempt_was_in_progress;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    if (record.attempt_was_in_progress)
        ESP_LOGW(TAG, "Recovered interrupted automatic renewal attempt; persisted cooldown retained");
    return ESP_OK;
}

static void tls_activation_outcome_publish(const tls_activation_outcome_record_t *record)
{
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.tls_activation_outcome_state_loaded = true;
    s_renewal_scheduler_status.tls_activation_last_result_valid = record->result_valid;
    s_renewal_scheduler_status.tls_activation_last_success = record->success;
    s_renewal_scheduler_status.tls_activation_last_lkg_restored = record->lkg_restored;
    s_renewal_scheduler_status.tls_activation_last_completed_unix = record->completed_unix;
    s_renewal_scheduler_status.tls_activation_last_transition_result = record->transition_result;
    snprintf(s_renewal_scheduler_status.tls_activation_last_target_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_activation_last_target_leaf_sha256), "%s",
             record->target_leaf_sha256);
    snprintf(s_renewal_scheduler_status.tls_activation_last_running_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_activation_last_running_leaf_sha256), "%s",
             record->running_leaf_sha256);
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
}

static esp_err_t tls_activation_outcome_load(void)
{
    tls_activation_outcome_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION;

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        tls_activation_outcome_publish(&record);
        return ESP_OK;
    }
    if (err != ESP_OK) return err;

    size_t length = sizeof(record);
    err = nvs_get_blob(handle, APP_TLS_ACTIVATION_OUTCOME_KEY, &record, &length);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        memset(&record, 0, sizeof(record));
        record.version = APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION;
        tls_activation_outcome_publish(&record);
        return ESP_OK;
    }
    if (err != ESP_OK) return err;
    if (length != sizeof(record) || record.version != APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION ||
        record.target_leaf_sha256[64] != '\0' || record.running_leaf_sha256[64] != '\0') {
        return ESP_ERR_INVALID_VERSION;
    }
    tls_activation_outcome_publish(&record);
    return ESP_OK;
}

static esp_err_t tls_activation_outcome_store(bool success, bool lkg_restored, esp_err_t transition_result,
                                              const char *target_leaf_sha256,
                                              const char *running_leaf_sha256)
{
    tls_activation_outcome_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION;
    record.result_valid = true;
    record.success = success;
    record.lkg_restored = lkg_restored;
    record.transition_result = transition_result;
    (void)get_current_unix_time(&record.completed_unix);
    if (target_leaf_sha256 != NULL)
        snprintf(record.target_leaf_sha256, sizeof(record.target_leaf_sha256), "%s", target_leaf_sha256);
    if (running_leaf_sha256 != NULL)
        snprintf(record.running_leaf_sha256, sizeof(record.running_leaf_sha256), "%s", running_leaf_sha256);

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open_from_partition("nvs_certs", "acme", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, APP_TLS_ACTIVATION_OUTCOME_KEY, &record, sizeof(record));
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err == ESP_OK) tls_activation_outcome_publish(&record);
    return err;
}

static void tls_handoff_publish(const tls_handoff_record_t *record)
{
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.tls_handoff_state_loaded = true;
    s_renewal_scheduler_status.tls_handoff_in_progress = record->in_progress;
    s_renewal_scheduler_status.tls_handoff_recovered_interrupted = record->recovered_interrupted;
    s_renewal_scheduler_status.tls_handoff_attempt_count = record->attempt_count;
    s_renewal_scheduler_status.tls_handoff_started_unix = record->started_unix;
    s_renewal_scheduler_status.tls_handoff_retry_not_before_unix = record->retry_not_before_unix;
    snprintf(s_renewal_scheduler_status.tls_handoff_target_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_handoff_target_leaf_sha256), "%s",
             record->target_leaf_sha256);
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
}

static esp_err_t tls_handoff_write(const tls_handoff_record_t *record)
{
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open_from_partition("nvs_certs", "acme", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, APP_TLS_HANDOFF_KEY, record, sizeof(*record));
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err == ESP_OK) tls_handoff_publish(record);
    return err;
}

static esp_err_t tls_handoff_read(tls_handoff_record_t *record)
{
    if (record == NULL) return ESP_ERR_INVALID_ARG;
    memset(record, 0, sizeof(*record));
    record->version = APP_TLS_HANDOFF_RECORD_VERSION;
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    size_t length = sizeof(*record);
    err = nvs_get_blob(handle, APP_TLS_HANDOFF_KEY, record, &length);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        memset(record, 0, sizeof(*record));
        record->version = APP_TLS_HANDOFF_RECORD_VERSION;
        return ESP_OK;
    }
    if (err != ESP_OK) return err;
    if (length != sizeof(*record) || record->version != APP_TLS_HANDOFF_RECORD_VERSION ||
        record->target_leaf_sha256[64] != '\0') return ESP_ERR_INVALID_VERSION;
    return ESP_OK;
}

static esp_err_t tls_handoff_load_and_reconcile(void)
{
    tls_handoff_record_t record;
    esp_err_t err = tls_handoff_read(&record);
    if (err != ESP_OK) return err;
    if (record.in_progress) {
        int64_t now = 0;
        (void)get_current_unix_time(&now);
        record.in_progress = false;
        record.recovered_interrupted = true;
        if (now > 0 && record.retry_not_before_unix < now + APP_TLS_HANDOFF_RETRY_SECONDS)
            record.retry_not_before_unix = now + APP_TLS_HANDOFF_RETRY_SECONDS;
        err = tls_handoff_write(&record);
        if (err != ESP_OK) return err;
        ESP_LOGW(TAG, "Recovered interrupted automatic TLS handoff; retry cooldown retained");
    } else {
        tls_handoff_publish(&record);
    }
    return ESP_OK;
}

static esp_err_t tls_handoff_begin(const char *target_leaf_sha256, int64_t now)
{
    if (target_leaf_sha256 == NULL || target_leaf_sha256[0] == '\0' || now <= 0)
        return ESP_ERR_INVALID_ARG;
    tls_handoff_record_t record;
    esp_err_t err = tls_handoff_read(&record);
    if (err != ESP_OK) return err;
    if (record.in_progress) return ESP_ERR_INVALID_STATE;
    if (record.retry_not_before_unix > 0 && now < record.retry_not_before_unix)
        return ESP_ERR_TIMEOUT;
    record.version = APP_TLS_HANDOFF_RECORD_VERSION;
    record.in_progress = true;
    record.recovered_interrupted = false;
    record.attempt_count++;
    record.started_unix = now;
    record.retry_not_before_unix = now + APP_TLS_HANDOFF_RETRY_SECONDS;
    snprintf(record.target_leaf_sha256, sizeof(record.target_leaf_sha256), "%s", target_leaf_sha256);
    return tls_handoff_write(&record);
}

static esp_err_t tls_handoff_finish(bool success, int64_t now)
{
    tls_handoff_record_t record;
    esp_err_t err = tls_handoff_read(&record);
    if (err != ESP_OK) return err;
    record.in_progress = false;
    record.recovered_interrupted = false;
    if (success) {
        record.retry_not_before_unix = 0;
        record.target_leaf_sha256[0] = '\0';
    } else if (now > 0) {
        record.retry_not_before_unix = now + APP_TLS_HANDOFF_RETRY_SECONDS;
    }
    return tls_handoff_write(&record);
}

static void tls_activation_intent_publish(const acme_tls_activation_intent_record_t *record,
                                          const char *result)
{
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.tls_activation_intent_state_loaded = true;
    s_renewal_scheduler_status.tls_activation_intent_pending = record->pending;
    s_renewal_scheduler_status.tls_activation_boot_reconciled = record->boot_reconciled;
    s_renewal_scheduler_status.tls_activation_intent_created_unix = record->created_unix;
    snprintf(s_renewal_scheduler_status.tls_activation_intent_previous_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_activation_intent_previous_leaf_sha256),
             "%s", record->previous_leaf_sha256);
    snprintf(s_renewal_scheduler_status.tls_activation_intent_target_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_activation_intent_target_leaf_sha256),
             "%s", record->target_leaf_sha256);
    snprintf(s_renewal_scheduler_status.tls_activation_reconciliation_result,
             sizeof(s_renewal_scheduler_status.tls_activation_reconciliation_result),
             "%s", result != NULL ? result : "none");
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
}

static esp_err_t tls_activation_intent_clear(bool boot_reconciled)
{
    acme_tls_activation_intent_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = ACME_TLS_ACTIVATION_INTENT_RECORD_VERSION;
    record.boot_reconciled = boot_reconciled;
    esp_err_t err = acme_client_store_tls_activation_intent(&record);
    if (err == ESP_OK)
        tls_activation_intent_publish(&record, boot_reconciled ? "resolved_on_boot" : "cleared_no_replacement");
    return err;
}

static esp_err_t tls_activation_intent_begin(const char *previous_leaf_sha256, int64_t now)
{
    if (previous_leaf_sha256 == NULL || previous_leaf_sha256[0] == '\0') return ESP_ERR_INVALID_ARG;
    acme_tls_activation_intent_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = ACME_TLS_ACTIVATION_INTENT_RECORD_VERSION;
    record.pending = true;
    record.created_unix = now;
    snprintf(record.previous_leaf_sha256, sizeof(record.previous_leaf_sha256), "%s", previous_leaf_sha256);
    esp_err_t err = acme_client_store_tls_activation_intent(&record);
    if (err == ESP_OK) tls_activation_intent_publish(&record, "pending_target_unknown");
    return err;
}

static esp_err_t tls_activation_intent_set_target(const char *target_leaf_sha256)
{
    if (target_leaf_sha256 == NULL || target_leaf_sha256[0] == '\0') return ESP_ERR_INVALID_ARG;
    acme_tls_activation_intent_record_t record;
    esp_err_t err = acme_client_load_tls_activation_intent(&record);
    if (err != ESP_OK) return err;
    if (!record.pending) return ESP_ERR_INVALID_STATE;
    snprintf(record.target_leaf_sha256, sizeof(record.target_leaf_sha256), "%s", target_leaf_sha256);
    err = acme_client_store_tls_activation_intent(&record);
    if (err == ESP_OK) tls_activation_intent_publish(&record, "pending_runtime_handoff");
    return err;
}

static esp_err_t tls_activation_intent_load_and_reconcile(void)
{
    acme_tls_activation_intent_record_t record;
    esp_err_t err = acme_client_load_tls_activation_intent(&record);
    if (err != ESP_OK) return err;

    if (!record.pending) {
        tls_activation_intent_publish(&record, record.boot_reconciled ? "resolved_on_boot" : "none");
        return ESP_OK;
    }

    if (s_tls_source == WEB_TLS_PRODUCTION && s_active_server_leaf_sha256[0] != '\0') {
        if (record.target_leaf_sha256[0] != '\0' &&
            strcmp(record.target_leaf_sha256, s_active_server_leaf_sha256) == 0) {
            return tls_activation_intent_clear(true);
        }
        if (record.target_leaf_sha256[0] == '\0' &&
            record.previous_leaf_sha256[0] != '\0' &&
            strcmp(record.previous_leaf_sha256, s_active_server_leaf_sha256) != 0) {
            /* Power loss after dual-slot selector commit but before target fingerprint
             * was persisted. The production boot path has already loaded the new,
             * validated selected credential, so reconcile the interrupted intent. */
            return tls_activation_intent_clear(true);
        }
        if (record.target_leaf_sha256[0] == '\0' &&
            record.previous_leaf_sha256[0] != '\0' &&
            strcmp(record.previous_leaf_sha256, s_active_server_leaf_sha256) == 0) {
            return tls_activation_intent_clear(false);
        }
    }

    tls_activation_intent_publish(&record, "pending_runtime_handoff");
    return ESP_OK;
}

/* Schedule a real production TLS handoff only for a persisted, fully identified
 * replacement target.  Operator-selected embedded/staging TLS is never
 * overridden by the automatic path. */
static esp_err_t tls_activation_schedule_pending_target(void)
{
    acme_tls_activation_intent_record_t intent;
    esp_err_t err = acme_client_load_tls_activation_intent(&intent);
    if (err != ESP_OK) return err;
    if (!intent.pending || intent.target_leaf_sha256[0] == '\0') return ESP_ERR_INVALID_STATE;
    if (s_tls_source != WEB_TLS_PRODUCTION || s_active_server_leaf_sha256[0] == '\0')
        return ESP_ERR_INVALID_STATE;

    acme_certificate_inspection_t candidate;
    memset(&candidate, 0, sizeof(candidate));
    err = acme_client_inspect_stored_production_certificate(&candidate);
    if (err != ESP_OK || !candidate.certificate_parse_valid ||
        !candidate.private_key_matches_certificate ||
        !candidate.hostname_matches_certificate ||
        strcmp(candidate.leaf_sha256, intent.target_leaf_sha256) != 0) {
        return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    }

    acme_renewal_scheduler_status_t preflight;
    memset(&preflight, 0, sizeof(preflight));
    evaluate_tls_activation_preflight(&preflight, &candidate);
    if (!preflight.tls_activation_preflight_ready) return ESP_ERR_INVALID_STATE;

    int64_t handoff_now = 0;
    if (!get_current_unix_time(&handoff_now) || handoff_now <= 0) return ESP_ERR_INVALID_STATE;
    err = tls_handoff_begin(intent.target_leaf_sha256, handoff_now);
    if (err != ESP_OK) return err;

    if (!tls_transition_try_claim()) {
        (void)tls_handoff_finish(false, handoff_now);
        return ESP_ERR_INVALID_STATE;
    }
    s_tls_transition_automatic = true;
    if (xTaskCreate(tls_transition_task, "tls_auto", 8192U,
                    (void *)(uintptr_t)WEB_TLS_PRODUCTION, 5U, NULL) != pdPASS) {
        s_tls_transition_automatic = false;
        tls_transition_release();
        (void)tls_handoff_finish(false, handoff_now);
        return ESP_ERR_NO_MEM;
    }

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.tls_activation_in_progress = true;
    s_renewal_scheduler_status.tls_activation_preflight_ready = false;
    snprintf(s_renewal_scheduler_status.tls_activation_preflight_result,
             sizeof(s_renewal_scheduler_status.tls_activation_preflight_result),
             "activation_scheduled");
    snprintf(s_renewal_scheduler_status.tls_activation_reconciliation_result,
             sizeof(s_renewal_scheduler_status.tls_activation_reconciliation_result),
             "runtime_handoff_scheduled");
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    return ESP_OK;
}

static void renewal_scheduler_execute_if_ready(void)
{
    acme_renewal_scheduler_status_t snapshot;
    int64_t now = 0;

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    snapshot = s_renewal_scheduler_status;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    if (!snapshot.execution_preflight_ready || !snapshot.eligible ||
        snapshot.attempt_in_progress) {
        return;
    }
    if (!get_current_unix_time(&now) || now <= 0) {
        ESP_LOGW(TAG, "Automatic renewal execution skipped: disciplined time unavailable");
        return;
    }

    /* Atomically consume the preflight gate and acquire the attempt lock. */
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    if (!s_renewal_scheduler_status.execution_preflight_ready ||
        s_renewal_scheduler_status.attempt_in_progress ||
        (s_renewal_scheduler_status.retry_not_before_unix > 0 &&
         now < s_renewal_scheduler_status.retry_not_before_unix)) {
        portEXIT_CRITICAL(&s_renewal_scheduler_lock);
        return;
    }
    s_renewal_scheduler_status.attempt_in_progress = true;
    s_renewal_scheduler_status.execution_preflight_ready = false;
    s_renewal_scheduler_status.attempt_count++;
    s_renewal_scheduler_status.last_attempt_unix = now;
    s_renewal_scheduler_status.retry_not_before_unix =
        now + APP_ACME_RENEWAL_ATTEMPT_COOLDOWN_SECONDS;
    s_renewal_scheduler_status.last_attempt_result_valid = false;
    s_renewal_scheduler_status.last_attempt_result = ESP_OK;
    s_renewal_scheduler_status.last_transaction_stage = ACME_PRODUCTION_TRANSACTION_STAGE_NONE;
    s_renewal_scheduler_status.last_transaction_completed = false;
    s_renewal_scheduler_status.last_dns01_prepared = false;
    s_renewal_scheduler_status.last_cleanup_attempted = false;
    s_renewal_scheduler_status.last_cleanup_result = ESP_OK;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    esp_err_t persist_err = renewal_scheduler_persist_attempt_state(true);
    if (persist_err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal attempt-state commit failed: %s; refusing ACME execution",
                 esp_err_to_name(persist_err));
        portENTER_CRITICAL(&s_renewal_scheduler_lock);
        s_renewal_scheduler_status.attempt_in_progress = false;
        s_renewal_scheduler_status.execution_preflight_ready = false;
        portEXIT_CRITICAL(&s_renewal_scheduler_lock);
        return;
    }

    esp_err_t result = ESP_FAIL;
    acme_production_transaction_status_t transaction;
    memset(&transaction, 0, sizeof(transaction));
    acme_certificate_inspection_t certificate;
    memset(&certificate, 0, sizeof(certificate));

    result = acme_client_inspect_stored_production_certificate(&certificate);
    if (result != ESP_OK || !certificate.certificate_parse_valid ||
        !certificate.hostname_matches_certificate ||
        !certificate.private_key_matches_certificate ||
        certificate.hostname[0] == '\0') {
        ESP_LOGE(TAG, "Automatic renewal aborted: production credential inspection failed: %s",
                 esp_err_to_name(result));
        if (result == ESP_OK) result = ESP_ERR_INVALID_STATE;
        goto complete;
    }

    device_config_snapshot_t config;
    result = device_config_get_snapshot(&config);
    if (result != ESP_OK || !config.cloudflare_configured ||
        !hostname_in_zone(certificate.hostname, config.cloudflare_zone_name)) {
        ESP_LOGE(TAG, "Automatic renewal aborted: Cloudflare configuration/zone preflight failed");
        if (result == ESP_OK) result = ESP_ERR_INVALID_STATE;
        goto complete;
    }

    renewal_dns01_context_t dns;
    memset(&dns, 0, sizeof(dns));
    result = device_config_get_cloudflare_credentials(&dns.credentials);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal aborted: Cloudflare credentials unavailable: %s",
                 esp_err_to_name(result));
        goto clear_dns_context;
    }

    acme_production_dns01_hooks_t hooks = {
        .prepare_dns01 = renewal_dns01_prepare,
        .cleanup_dns01 = renewal_dns01_cleanup,
        .context = &dns,
    };

    /* Persist activation intent immediately before the transaction can replace
     * the selected production slot. No TLS transition is scheduled in 5B.10f.3c. */
    result = tls_activation_intent_begin(certificate.leaf_sha256, now);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal aborted: TLS activation intent commit failed: %s",
                 esp_err_to_name(result));
        goto clear_dns_context;
    }

    ESP_LOGI(TAG, "Automatic production renewal attempt starting for %s; TLS activation disabled",
             certificate.hostname);
    result = acme_client_run_production_certificate_transaction(
        certificate.hostname, &hooks, &transaction);

    if (transaction.certificate.stored) {
        acme_certificate_inspection_t replacement;
        memset(&replacement, 0, sizeof(replacement));
        const esp_err_t inspect_replacement =
            acme_client_inspect_stored_production_certificate(&replacement);
        if (inspect_replacement == ESP_OK && replacement.certificate_parse_valid &&
            replacement.private_key_matches_certificate && replacement.leaf_sha256[0] != '\0') {
            const esp_err_t intent_err = tls_activation_intent_set_target(replacement.leaf_sha256);
            if (intent_err != ESP_OK) {
                ESP_LOGE(TAG, "Replacement stored but TLS activation target persistence failed: %s",
                         esp_err_to_name(intent_err));
            } else {
                const esp_err_t activation_err = tls_activation_schedule_pending_target();
                if (activation_err != ESP_OK) {
                    ESP_LOGE(TAG, "Replacement stored but automatic TLS handoff was not scheduled: %s",
                             esp_err_to_name(activation_err));
                } else {
                    ESP_LOGI(TAG, "Automatic production TLS handoff scheduled for replacement %s",
                             replacement.leaf_sha256);
                }
            }
        } else {
            ESP_LOGE(TAG, "Replacement stored but TLS activation target inspection failed: %s",
                     esp_err_to_name(inspect_replacement));
        }
    } else {
        const esp_err_t intent_err = tls_activation_intent_clear(false);
        if (intent_err != ESP_OK)
            ESP_LOGE(TAG, "TLS activation intent cleanup after non-replacement failed: %s",
                     esp_err_to_name(intent_err));
    }

    ESP_LOGI(TAG,
             "Automatic production renewal attempt finished: result=%s completed=%d "
             "dns_prepared=%d cleanup_attempted=%d cleanup_result=%s "
             "automatic_tls_activation=true",
             esp_err_to_name(result), transaction.completed,
             transaction.dns01_prepared, transaction.cleanup_attempted,
             esp_err_to_name(transaction.cleanup_result));

clear_dns_context:
    memset(dns.credentials.api_token, 0, sizeof(dns.credentials.api_token));
    memset(&dns, 0, sizeof(dns));

complete:
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.attempt_in_progress = false;
    s_renewal_scheduler_status.execution_preflight_ready = false;
    s_renewal_scheduler_status.last_attempt_result_valid = true;
    s_renewal_scheduler_status.last_attempt_result = result;
    s_renewal_scheduler_status.last_transaction_stage = transaction.stage;
    s_renewal_scheduler_status.last_transaction_completed = transaction.completed;
    s_renewal_scheduler_status.last_dns01_prepared = transaction.dns01_prepared;
    s_renewal_scheduler_status.last_cleanup_attempted = transaction.cleanup_attempted;
    s_renewal_scheduler_status.last_cleanup_result = transaction.cleanup_result;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    persist_err = renewal_scheduler_persist_attempt_state(false);
    if (persist_err != ESP_OK)
        ESP_LOGE(TAG, "Automatic renewal final attempt-state commit failed: %s", esp_err_to_name(persist_err));

    if (result != ESP_OK) {
        ESP_LOGE(TAG, "Automatic production renewal attempt failed: %s; cooldown remains armed",
                 esp_err_to_name(result));
    }
}

static void renewal_scheduler_evaluate(void)
{
    acme_renewal_scheduler_status_t next = {0};
    acme_certificate_inspection_t certificate;
    int64_t now = 0;
    int64_t expires = 0;

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    next.task_started = s_renewal_scheduler_status.task_started;
    next.evaluation_count = s_renewal_scheduler_status.evaluation_count + 1U;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    next.evaluated = true;

    const esp_err_t inspect_err =
        acme_client_inspect_stored_production_certificate(&certificate);
    if (inspect_err == ESP_ERR_NOT_FOUND) {
        next.state = ACME_RENEWAL_SCHEDULER_NO_CERTIFICATE;
    } else if (inspect_err != ESP_OK && inspect_err != ESP_ERR_INVALID_STATE) {
        next.state = ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE;
    } else if (!certificate.certificate_parse_valid ||
               !certificate.hostname_matches_certificate ||
               !certificate.private_key_matches_certificate ||
               !parse_utc_timestamp(certificate.valid_to, &expires)) {
        next.state = ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE;
    } else if (!get_current_unix_time(&now)) {
        next.state = ACME_RENEWAL_SCHEDULER_TIME_UNAVAILABLE;
    } else {
        next.last_evaluation_unix = now;
        next.seconds_remaining = expires - now;
        next.days_remaining = next.seconds_remaining >= 0
                                  ? next.seconds_remaining / 86400LL
                                  : -((-next.seconds_remaining + 86399LL) / 86400LL);
        if (next.seconds_remaining <= 0) {
            next.state = ACME_RENEWAL_SCHEDULER_EXPIRED;
        } else if (next.seconds_remaining <= 7LL * 86400LL) {
            next.state = ACME_RENEWAL_SCHEDULER_URGENT;
        } else if (next.seconds_remaining <= 30LL * 86400LL) {
            next.state = ACME_RENEWAL_SCHEDULER_DUE;
        } else {
            next.state = ACME_RENEWAL_SCHEDULER_VALID;
        }
    }

    bool automatic_enabled = false;
    const esp_err_t policy_err = acme_client_get_automatic_renewal_enabled(&automatic_enabled);
    if (policy_err != ESP_OK) {
        ESP_LOGE(TAG, "ACME renewal policy read failed: %s; forcing disabled", esp_err_to_name(policy_err));
        automatic_enabled = false;
    }
    next.automatic_renewal_enabled = automatic_enabled;
    next.eligible = automatic_enabled &&
                    (next.state == ACME_RENEWAL_SCHEDULER_DUE ||
                     next.state == ACME_RENEWAL_SCHEDULER_URGENT ||
                     next.state == ACME_RENEWAL_SCHEDULER_EXPIRED);

    /* Preserve execution accounting across evaluations. A genuine due/urgent/
     * expired evaluation may be consumed by the scheduler task after this
     * state is published. */
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    next.attempt_in_progress = s_renewal_scheduler_status.attempt_in_progress;
    next.attempt_count = s_renewal_scheduler_status.attempt_count;
    next.last_attempt_unix = s_renewal_scheduler_status.last_attempt_unix;
    next.retry_not_before_unix = s_renewal_scheduler_status.retry_not_before_unix;
    next.last_attempt_result_valid = s_renewal_scheduler_status.last_attempt_result_valid;
    next.last_attempt_result = s_renewal_scheduler_status.last_attempt_result;
    next.last_transaction_stage = s_renewal_scheduler_status.last_transaction_stage;
    next.last_transaction_completed = s_renewal_scheduler_status.last_transaction_completed;
    next.last_dns01_prepared = s_renewal_scheduler_status.last_dns01_prepared;
    next.last_cleanup_attempted = s_renewal_scheduler_status.last_cleanup_attempted;
    next.last_cleanup_result = s_renewal_scheduler_status.last_cleanup_result;
    next.attempt_state_loaded = s_renewal_scheduler_status.attempt_state_loaded;
    next.recovered_interrupted_attempt = s_renewal_scheduler_status.recovered_interrupted_attempt;
    next.tls_activation_intent_state_loaded = s_renewal_scheduler_status.tls_activation_intent_state_loaded;
    next.tls_activation_intent_pending = s_renewal_scheduler_status.tls_activation_intent_pending;
    next.tls_activation_boot_reconciled = s_renewal_scheduler_status.tls_activation_boot_reconciled;
    next.tls_activation_intent_created_unix = s_renewal_scheduler_status.tls_activation_intent_created_unix;
    snprintf(next.tls_activation_intent_previous_leaf_sha256,
             sizeof(next.tls_activation_intent_previous_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_activation_intent_previous_leaf_sha256);
    snprintf(next.tls_activation_intent_target_leaf_sha256,
             sizeof(next.tls_activation_intent_target_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_activation_intent_target_leaf_sha256);
    snprintf(next.tls_activation_reconciliation_result,
             sizeof(next.tls_activation_reconciliation_result), "%s",
             s_renewal_scheduler_status.tls_activation_reconciliation_result);

    /* 5B.10g.1.1: protected automatic TLS activation outcome state is loaded
     * before the scheduler task starts. Preserve it across each freshly built
     * evaluation snapshot just like attempt and activation-intent state. */
    next.tls_activation_outcome_state_loaded =
        s_renewal_scheduler_status.tls_activation_outcome_state_loaded;
    next.tls_activation_last_result_valid =
        s_renewal_scheduler_status.tls_activation_last_result_valid;
    next.tls_activation_last_success =
        s_renewal_scheduler_status.tls_activation_last_success;
    next.tls_activation_last_lkg_restored =
        s_renewal_scheduler_status.tls_activation_last_lkg_restored;
    next.tls_activation_last_completed_unix =
        s_renewal_scheduler_status.tls_activation_last_completed_unix;
    next.tls_activation_last_transition_result =
        s_renewal_scheduler_status.tls_activation_last_transition_result;
    snprintf(next.tls_activation_last_target_leaf_sha256,
             sizeof(next.tls_activation_last_target_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_activation_last_target_leaf_sha256);
    snprintf(next.tls_activation_last_running_leaf_sha256,
             sizeof(next.tls_activation_last_running_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_activation_last_running_leaf_sha256);
    next.tls_handoff_state_loaded = s_renewal_scheduler_status.tls_handoff_state_loaded;
    next.tls_handoff_in_progress = s_renewal_scheduler_status.tls_handoff_in_progress;
    next.tls_handoff_recovered_interrupted = s_renewal_scheduler_status.tls_handoff_recovered_interrupted;
    next.tls_handoff_attempt_count = s_renewal_scheduler_status.tls_handoff_attempt_count;
    next.tls_handoff_started_unix = s_renewal_scheduler_status.tls_handoff_started_unix;
    next.tls_handoff_retry_not_before_unix = s_renewal_scheduler_status.tls_handoff_retry_not_before_unix;
    snprintf(next.tls_handoff_target_leaf_sha256, sizeof(next.tls_handoff_target_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_handoff_target_leaf_sha256);
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    const bool cooldown_clear = next.last_attempt_unix == 0 || now <= 0 ||
                                now >= next.retry_not_before_unix;
    next.execution_preflight_ready = next.eligible && !next.attempt_in_progress && cooldown_clear;

    /* 5B.10f.1: observe whether the stored production credential would be a
     * safe, distinct TLS handoff candidate. This is deliberately non-activating. */
    if (inspect_err == ESP_OK || inspect_err == ESP_ERR_INVALID_STATE) {
        evaluate_tls_activation_preflight(&next, &certificate);
    } else {
        evaluate_tls_activation_preflight(&next, NULL);
    }

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status = next;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    ESP_LOGI(TAG, "ACME renewal scheduler evaluation: state=%s days_remaining=%" PRId64
                  " enabled=%d eligible=%d automatic_execution=%d",
             renewal_scheduler_state_name(next.state), next.days_remaining,
             next.automatic_renewal_enabled, next.eligible,
             next.execution_preflight_ready);
}

static void renewal_scheduler_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(APP_ACME_RENEWAL_INITIAL_DELAY_MS));
    for (;;) {
        renewal_scheduler_evaluate();
        renewal_scheduler_execute_if_ready();

        /* Retry a persisted, identified replacement target at scheduler cadence. */
        acme_tls_activation_intent_record_t pending_intent;
        if (acme_client_load_tls_activation_intent(&pending_intent) == ESP_OK &&
            pending_intent.pending && pending_intent.target_leaf_sha256[0] != '\0' &&
            !s_tls_transition_pending) {
            const esp_err_t activation_err = tls_activation_schedule_pending_target();
            if (activation_err != ESP_OK && activation_err != ESP_ERR_INVALID_STATE)
                ESP_LOGW(TAG, "Pending automatic TLS handoff retry not scheduled: %s",
                         esp_err_to_name(activation_err));
        }
        vTaskDelay(pdMS_TO_TICKS(APP_ACME_RENEWAL_CHECK_INTERVAL_MS));
    }
}

static esp_err_t start_renewal_scheduler(void)
{
    if (s_renewal_scheduler_task != NULL) return ESP_OK;

    const esp_err_t intent_err = tls_activation_intent_load_and_reconcile();
    if (intent_err != ESP_OK) {
        ESP_LOGE(TAG, "TLS activation intent load/reconciliation failed: %s", esp_err_to_name(intent_err));
        return intent_err;
    }

    const esp_err_t outcome_err = tls_activation_outcome_load();
    if (outcome_err != ESP_OK) {
        ESP_LOGE(TAG, "TLS activation outcome-state load failed: %s", esp_err_to_name(outcome_err));
        return outcome_err;
    }

    const esp_err_t handoff_err = tls_handoff_load_and_reconcile();
    if (handoff_err != ESP_OK) {
        ESP_LOGE(TAG, "TLS handoff-state load/reconciliation failed: %s", esp_err_to_name(handoff_err));
        return handoff_err;
    }

    const esp_err_t load_err = renewal_scheduler_load_attempt_state();
    if (load_err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal persisted attempt-state load failed: %s", esp_err_to_name(load_err));
        return load_err;
    }

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.task_started = true;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    BaseType_t created = xTaskCreate(renewal_scheduler_task,
                                     "acme_renewal",
                                     APP_ACME_RENEWAL_TASK_STACK_SIZE,
                                     NULL,
                                     APP_ACME_RENEWAL_TASK_PRIORITY,
                                     &s_renewal_scheduler_task);
    if (created != pdPASS) {
        portENTER_CRITICAL(&s_renewal_scheduler_lock);
        s_renewal_scheduler_status.task_started = false;
        portEXIT_CRITICAL(&s_renewal_scheduler_lock);
        s_renewal_scheduler_task = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static void set_security_headers(httpd_req_t *request);

static const char *renewal_eligibility_reason(const acme_renewal_scheduler_status_t *status)
{
    if (!status->automatic_renewal_enabled) return "disabled";
    if (!status->evaluated) return "not_evaluated";
    switch (status->state) {
    case ACME_RENEWAL_SCHEDULER_DUE: return "renewal_window";
    case ACME_RENEWAL_SCHEDULER_URGENT: return "urgent_window";
    case ACME_RENEWAL_SCHEDULER_EXPIRED: return "expired";
    case ACME_RENEWAL_SCHEDULER_TIME_UNAVAILABLE: return "time_unavailable";
    case ACME_RENEWAL_SCHEDULER_NO_CERTIFICATE: return "no_certificate";
    case ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE: return "invalid_certificate";
    default: return "not_due";
    }
}

static esp_err_t acme_production_renewal_scheduler_handler(httpd_req_t *request)
{
    acme_renewal_scheduler_status_t status;
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    status = s_renewal_scheduler_status;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    /* Refresh the persisted switch for immediate management visibility without
     * changing the most recent certificate evaluation result. */
    bool persisted_enabled = false;
    if (acme_client_get_automatic_renewal_enabled(&persisted_enabled) == ESP_OK) {
        status.automatic_renewal_enabled = persisted_enabled;
        status.eligible = persisted_enabled && status.evaluated &&
            (status.state == ACME_RENEWAL_SCHEDULER_DUE ||
             status.state == ACME_RENEWAL_SCHEDULER_URGENT ||
             status.state == ACME_RENEWAL_SCHEDULER_EXPIRED);
    } else {
        status.automatic_renewal_enabled = false;
        status.eligible = false;
    }

    const int64_t next_check = status.last_evaluation_unix > 0
                                 ? status.last_evaluation_unix + 21600LL : 0LL;
    char response[3072];
    const int length = snprintf(response, sizeof(response),
        "{\"enabled\":true,\"mode\":\"automatic_execution\","
        "\"automatic_renewal_enabled\":%s,\"automatic_certificate_replacement\":true,"
        "\"automatic_tls_activation\":true,\"automatic_acme_execution\":true,"
        "\"eligible\":%s,\"eligibility_reason\":\"%s\","
        "\"execution_preflight_ready\":%s,\"attempt_in_progress\":%s,"
        "\"attempt_count\":%" PRIu32 ",\"last_attempt_unix\":%" PRId64 ","
        "\"retry_not_before_unix\":%" PRId64 ",\"attempt_cooldown_seconds\":21600,"
        "\"last_attempt_result_valid\":%s,\"last_attempt_result\":\"%s\","
        "\"last_transaction_stage\":\"%s\",\"last_transaction_completed\":%s,"
        "\"last_dns01_prepared\":%s,\"last_cleanup_attempted\":%s,"
        "\"last_cleanup_result\":\"%s\","
        "\"attempt_observability_persistent\":true,""\"attempt_state_loaded\":%s,\"recovered_interrupted_attempt\":%s,"
        "\"tls_activation_preflight_evaluated\":%s,\"tls_activation_preflight_ready\":%s,"
        "\"tls_candidate_valid\":%s,\"tls_candidate_hostname_match\":%s,"
        "\"tls_candidate_time_valid\":%s,\"tls_candidate_fingerprint_changed\":%s,"
        "\"tls_activation_in_progress\":%s,\"tls_candidate_leaf_sha256\":\"%s\","
        "\"tls_current_leaf_sha256\":\"%s\",\"tls_activation_preflight_result\":\"%s\","
        "\"tls_activation_intent_persistent\":true,\"tls_activation_intent_state_loaded\":%s,"
        "\"tls_activation_intent_pending\":%s,\"tls_activation_boot_reconciled\":%s,"
        "\"tls_activation_intent_created_unix\":%" PRId64 ","
        "\"tls_activation_intent_previous_leaf_sha256\":\"%s\","
        "\"tls_activation_intent_target_leaf_sha256\":\"%s\","
        "\"tls_activation_reconciliation_result\":\"%s\","
        "\"tls_activation_outcome_persistent\":true,\"tls_activation_outcome_state_loaded\":%s,"
        "\"tls_activation_last_result_valid\":%s,\"tls_activation_last_success\":%s,"
        "\"tls_activation_last_lkg_restored\":%s,\"tls_activation_last_completed_unix\":%" PRId64 ","
        "\"tls_activation_last_transition_result\":\"%s\","
        "\"tls_activation_last_target_leaf_sha256\":\"%s\","
        "\"tls_activation_last_running_leaf_sha256\":\"%s\","
        "\"tls_handoff_state_persistent\":true,\"tls_handoff_state_loaded\":%s,"
        "\"tls_handoff_in_progress\":%s,\"tls_handoff_recovered_interrupted\":%s,"
        "\"tls_handoff_attempt_count\":%" PRIu32 ",\"tls_handoff_started_unix\":%" PRId64 ","
        "\"tls_handoff_retry_not_before_unix\":%" PRId64 ",\"tls_handoff_target_leaf_sha256\":\"%s\","
        "\"tls_management_ca_unchanged\":true,"
        "\"task_started\":%s,\"evaluated\":%s,\"evaluation_count\":%" PRIu32 ","
        "\"check_interval_seconds\":21600,\"last_evaluation_unix\":%" PRId64 ","
        "\"next_check_unix\":%" PRId64 ",\"state\":\"%s\","
        "\"seconds_remaining\":%" PRId64 ",\"days_remaining\":%" PRId64 ","
        "\"renew_before_days\":30,\"urgent_before_days\":7}\n",
        status.automatic_renewal_enabled ? "true" : "false",
        status.eligible ? "true" : "false", renewal_eligibility_reason(&status),
        status.execution_preflight_ready ? "true" : "false",
        status.attempt_in_progress ? "true" : "false", status.attempt_count,
        status.last_attempt_unix, status.retry_not_before_unix,
        status.last_attempt_result_valid ? "true" : "false",
        status.last_attempt_result_valid ? esp_err_to_name(status.last_attempt_result) : "none",
        renewal_transaction_stage_to_string(status.last_transaction_stage),
        status.last_transaction_completed ? "true" : "false",
        status.last_dns01_prepared ? "true" : "false",
        status.last_cleanup_attempted ? "true" : "false",
        status.last_cleanup_attempted ? esp_err_to_name(status.last_cleanup_result) : "none",
        status.attempt_state_loaded ? "true" : "false",
        status.recovered_interrupted_attempt ? "true" : "false",
        status.tls_activation_preflight_evaluated ? "true" : "false",
        status.tls_activation_preflight_ready ? "true" : "false",
        status.tls_candidate_valid ? "true" : "false",
        status.tls_candidate_hostname_match ? "true" : "false",
        status.tls_candidate_time_valid ? "true" : "false",
        status.tls_candidate_fingerprint_changed ? "true" : "false",
        status.tls_activation_in_progress ? "true" : "false",
        status.tls_candidate_leaf_sha256, status.tls_current_leaf_sha256,
        status.tls_activation_preflight_result,
        status.tls_activation_intent_state_loaded ? "true" : "false",
        status.tls_activation_intent_pending ? "true" : "false",
        status.tls_activation_boot_reconciled ? "true" : "false",
        status.tls_activation_intent_created_unix,
        status.tls_activation_intent_previous_leaf_sha256,
        status.tls_activation_intent_target_leaf_sha256,
        status.tls_activation_reconciliation_result,
        status.tls_activation_outcome_state_loaded ? "true" : "false",
        status.tls_activation_last_result_valid ? "true" : "false",
        status.tls_activation_last_success ? "true" : "false",
        status.tls_activation_last_lkg_restored ? "true" : "false",
        status.tls_activation_last_completed_unix,
        status.tls_activation_last_result_valid ? esp_err_to_name(status.tls_activation_last_transition_result) : "none",
        status.tls_activation_last_target_leaf_sha256,
        status.tls_activation_last_running_leaf_sha256,
        status.tls_handoff_state_loaded ? "true" : "false",
        status.tls_handoff_in_progress ? "true" : "false",
        status.tls_handoff_recovered_interrupted ? "true" : "false",
        status.tls_handoff_attempt_count, status.tls_handoff_started_unix,
        status.tls_handoff_retry_not_before_unix, status.tls_handoff_target_leaf_sha256,
        status.task_started ? "true" : "false", status.evaluated ? "true" : "false",
        status.evaluation_count, status.last_evaluation_unix, next_check,
        renewal_scheduler_state_name(status.state), status.seconds_remaining, status.days_remaining);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_production_renewal_scheduler_put_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len >= 96)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected {\"enabled\":true|false}");
    char body[96]; size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int result = httpd_req_recv(request, body + received,
                                          (size_t)request->content_len - received);
        if (result == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (result <= 0) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "request body receive failed");
        received += (size_t)result;
    }
    body[received] = '\0';
    const char *key = strstr(body, "\"enabled\"");
    if (key == NULL) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected enabled boolean");
    const char *colon = strchr(key, ':');
    if (colon == NULL) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected enabled boolean");
    ++colon; while (*colon == ' ' || *colon == '\t' || *colon == '\r' || *colon == '\n') ++colon;
    bool enabled;
    if (strncmp(colon, "true", 4U) == 0) enabled = true;
    else if (strncmp(colon, "false", 5U) == 0) enabled = false;
    else return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected enabled boolean");

    const esp_err_t err = acme_client_set_automatic_renewal_enabled(enabled);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal policy commit failed: %s", esp_err_to_name(err));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "policy commit failed");
    }
    ESP_LOGI(TAG, "Automatic renewal policy %s; genuine due-window execution is %s; TLS auto-activation remains disabled",
             enabled ? "armed" : "disabled", enabled ? "armed" : "disabled");
    return acme_production_renewal_scheduler_handler(request);
}

static void set_security_headers(httpd_req_t *request)
{
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(request, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(request, "Referrer-Policy", "no-referrer");
}

static const char *reset_reason_to_string(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_POWERON:   return "POWER_ON";
    case ESP_RST_EXT:       return "EXTERNAL";
    case ESP_RST_SW:        return "SOFTWARE";
    case ESP_RST_PANIC:     return "PANIC";
    case ESP_RST_INT_WDT:   return "INTERRUPT_WATCHDOG";
    case ESP_RST_TASK_WDT:  return "TASK_WATCHDOG";
    case ESP_RST_WDT:       return "OTHER_WATCHDOG";
    case ESP_RST_DEEPSLEEP: return "DEEP_SLEEP";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_SDIO:      return "SDIO";
    case ESP_RST_USB:       return "USB";
    case ESP_RST_JTAG:      return "JTAG";
    case ESP_RST_EFUSE:     return "EFUSE";
    case ESP_RST_PWR_GLITCH:return "POWER_GLITCH";
    case ESP_RST_CPU_LOCKUP:return "CPU_LOCKUP";
    case ESP_RST_UNKNOWN:
    default:                return "UNKNOWN";
    }
}

static esp_err_t send_status_json(httpd_req_t *request)
{
    app_state_snapshot_t app_status;
    clock_discipline_status_t clock_status;
    gnss_service_status_t gnss_status;
    pps_service_status_t pps_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;
    nts_ke_stats_t nts_ke_stats;
    nts_ntp_auth_stats_t nts_auth_stats;

    (void)app_state_get_snapshot(&app_status);
    (void)clock_discipline_get_status(&clock_status);
    (void)gnss_service_get_status(&gnss_status);
    (void)pps_service_get_status(&pps_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);
    nts_ke_get_stats(&nts_ke_stats);
    nts_ntp_auth_get_stats(&nts_auth_stats);

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

    const int64_t uptime_us = esp_timer_get_time();
    const uint64_t uptime_seconds =
        uptime_us > 0 ? (uint64_t)(uptime_us / 1000000LL) : 0ULL;
    const bool boot_time_valid =
        current_time_valid && unix_now >= (int64_t)uptime_seconds;
    const int64_t boot_time_unix =
        boot_time_valid ? unix_now - (int64_t)uptime_seconds : 0;
    const char *reset_reason = reset_reason_to_string(esp_reset_reason());

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
        "\"system\":{"
        "\"uptime_seconds\":%" PRIu64 ","
        "\"boot_time_valid\":%s,"
        "\"boot_time_unix\":%" PRId64 ","
        "\"reset_reason\":\"%s\""
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
        "\"receiver_identity_valid\":%s,"
        "\"receiver_model\":\"%s\","
        "\"receiver_software_version\":\"%s\","
        "\"receiver_hardware_version\":\"%s\","
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
        "},"
        "\"nts\":{"
        "\"ke_running\":%s,"
        "\"ke_exchanges\":%" PRIu32 ","
        "\"ke_exchange_failures\":%" PRIu32 ","
        "\"ke_tls_handshake_failures\":%" PRIu32 ","
        "\"ke_alpn_rejections\":%" PRIu32 ","
        "\"verification_attempts\":%" PRIu32 ","
        "\"authenticated_requests\":%" PRIu32 ","
        "\"verification_failures\":%" PRIu32 ","
        "\"protected_responses\":%" PRIu32 ","
        "\"protection_failures\":%" PRIu32
        "}"
        "}",
        APP_WEB_CONSOLE_PORT,
        uptime_seconds,
        boot_time_valid ? "true" : "false",
        boot_time_unix,
        reset_reason,
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

        gnss_status.receiver_identity_valid ? "true" : "false",
        gnss_status.receiver_model,
        gnss_status.receiver_software_version,
        gnss_status.receiver_hardware_version,
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
        ntp_status.last_response_monotonic_us,

        nts_ke_stats.running ? "true" : "false",
        nts_ke_stats.exchanges_completed,
        nts_ke_stats.exchange_failures,
        nts_ke_stats.tls_handshake_failures,
        nts_ke_stats.alpn_rejections,
        nts_auth_stats.verification_attempts,
        nts_auth_stats.authenticated_requests,
        nts_auth_stats.verification_failures,
        nts_auth_stats.protected_responses,
        nts_auth_stats.protection_failures);

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
    nts_ke_stats_t nts_ke_stats;
    nts_ntp_auth_stats_t nts_auth_stats;

    (void)clock_discipline_get_status(&clock_status);
    (void)gnss_service_get_status(&gnss_status);
    (void)pps_service_get_status(&pps_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);
    nts_ke_get_stats(&nts_ke_stats);
    nts_ntp_auth_get_stats(&nts_auth_stats);

    char response[4096];

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
        "esp32_ntp_server_unsynchronized_drops_total %" PRIu32 "\n"
        "# HELP esp32_nts_ke_running NTS-KE service running state.\n"
        "# TYPE esp32_nts_ke_running gauge\n"
        "esp32_nts_ke_running %d\n"
        "# HELP esp32_nts_ke_exchanges_total Successful NTS-KE exchanges.\n"
        "# TYPE esp32_nts_ke_exchanges_total counter\n"
        "esp32_nts_ke_exchanges_total %" PRIu32 "\n"
        "# HELP esp32_nts_ke_exchange_failures_total Failed NTS-KE exchanges.\n"
        "# TYPE esp32_nts_ke_exchange_failures_total counter\n"
        "esp32_nts_ke_exchange_failures_total %" PRIu32 "\n"
        "# HELP esp32_nts_authenticated_requests_total Authenticated NTS NTP requests.\n"
        "# TYPE esp32_nts_authenticated_requests_total counter\n"
        "esp32_nts_authenticated_requests_total %" PRIu32 "\n"
        "# HELP esp32_nts_verification_failures_total NTS NTP verification failures.\n"
        "# TYPE esp32_nts_verification_failures_total counter\n"
        "esp32_nts_verification_failures_total %" PRIu32 "\n"
        "# HELP esp32_nts_protected_responses_total Protected NTS NTP responses.\n"
        "# TYPE esp32_nts_protected_responses_total counter\n"
        "esp32_nts_protected_responses_total %" PRIu32 "\n"
        "# HELP esp32_nts_protection_failures_total NTS response protection failures.\n"
        "# TYPE esp32_nts_protection_failures_total counter\n"
        "esp32_nts_protection_failures_total %" PRIu32 "\n",
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
        ntp_status.unsynchronized_drops,
        nts_ke_stats.running ? 1 : 0,
        nts_ke_stats.exchanges_completed,
        nts_ke_stats.exchange_failures,
        nts_auth_stats.authenticated_requests,
        nts_auth_stats.verification_failures,
        nts_auth_stats.protected_responses,
        nts_auth_stats.protection_failures);

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
    char expected_value[CLOUDFLARE_DNS01_VALUE_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "record_id", record_id, sizeof(record_id)) ||
        !dns_record_id_is_valid(record_id) ||
        !extract_json_string(body, "value", expected_value, sizeof(expected_value)) ||
        expected_value[0] == '\0') {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "expected valid record_id and exact value");
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
    err = cloudflare_client_verify_dns01_txt_content(credentials.api_token, credentials.zone_id,
                                                     record_id, record_name, expected_value, &http_status);
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
    char expected_value[CLOUDFLARE_DNS01_VALUE_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "record_id", record_id, sizeof(record_id)) ||
        !dns_record_id_is_valid(record_id) ||
        !extract_json_string(body, "value", expected_value, sizeof(expected_value)) ||
        expected_value[0] == '\0') {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "expected valid record_id and exact value");
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
    err = cloudflare_client_delete_dns01_txt_content(credentials.api_token, credentials.zone_id,
                                                     record_id, record_name, expected_value, &http_status);
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
        const esp_err_t delete_err = cloudflare_client_delete_dns01_txt_content(
            credentials.api_token, credentials.zone_id, record_id,
            order.dns01_record_name, order.dns01_value, &cf_delete_status);
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
        const esp_err_t delete_err=cloudflare_client_delete_dns01_txt_content(credentials.api_token,
            credentials.zone_id, record_id, order.dns01_record_name, order.dns01_value, &cf_delete_status);
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


static esp_err_t production_certificate_issue_for_hostname(httpd_req_t *request, const char *hostname)
{
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

    acme_account_status_t production_account; memset(&production_account,0,sizeof(production_account));
    err = acme_client_provision_production_account(&production_account);
    if (err != ESP_OK || !production_account.registered) {
        memset(credentials.api_token,0,sizeof(credentials.api_token));
        httpd_resp_set_status(request,"502 Bad Gateway");
        return httpd_resp_send(request,"ACME production account provisioning failed",HTTPD_RESP_USE_STRLEN);
    }

    acme_order_discovery_t order;
    err = acme_client_discover_production_order(hostname, &order);
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
        validation_err=acme_client_validate_production_dns01(&order,&validation);
    }

    if (dns_created) {
        const esp_err_t delete_err=cloudflare_client_delete_dns01_txt_content(credentials.api_token,
            credentials.zone_id, record_id, order.dns01_record_name, order.dns01_value, &cf_delete_status);
        dns_deleted=(delete_err==ESP_OK);
        if (delete_err != ESP_OK) ESP_LOGE(TAG,"ACME DNS-01 cleanup failed: %s http=%d record_id=%s",
                                           esp_err_to_name(delete_err),cf_delete_status,record_id);
    }
    memset(credentials.api_token,0,sizeof(credentials.api_token));

    acme_certificate_issue_status_t certificate; memset(&certificate,0,sizeof(certificate));
    esp_err_t certificate_err = validation_err;
    if (validation_err == ESP_OK && validation.valid && dns_deleted)
        certificate_err = acme_client_finalize_production_order(&order, &certificate);

    char *response=calloc(1U,4096U);
    if (response==NULL) return httpd_resp_send_err(request,HTTPD_500_INTERNAL_SERVER_ERROR,"out of memory");
    const int length=snprintf(response,4096U,
        "{\"environment\":\"production\",\"account_url\":\"%s\",\"identifier\":\"%s\"," 
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
        production_account.account_url,order.identifier,order.order_url,order.dns01_record_name,record_id,
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

static esp_err_t acme_production_certificate_issue_handler(httpd_req_t *request)
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

    acme_certificate_inspection_t existing;
    const esp_err_t inspect_err = acme_client_inspect_stored_production_certificate(&existing);
    if (inspect_err == ESP_OK && existing.certificate_parse_valid &&
        existing.hostname_matches_certificate && existing.private_key_matches_certificate) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request,
            "Production certificate already exists; use the controlled renewal endpoint",
            HTTPD_RESP_USE_STRLEN);
    }
    if (inspect_err != ESP_OK && inspect_err != ESP_ERR_NOT_FOUND)
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Production certificate inspection failed");

    return production_certificate_issue_for_hostname(request, hostname);
}

static esp_err_t acme_production_certificate_renew_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t status;
    const esp_err_t inspect_err = acme_client_inspect_stored_production_certificate(&status);
    if (inspect_err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "No production certificate exists; use initial issuance",
                               HTTPD_RESP_USE_STRLEN);
    }
    if (inspect_err != ESP_OK || !status.certificate_parse_valid ||
        !status.hostname_matches_certificate || !status.private_key_matches_certificate)
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Stored production certificate is not valid for renewal");

    int64_t now = 0, expires = 0;
    if (!get_current_unix_time(&now) || !parse_utc_timestamp(status.valid_to, &expires)) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Disciplined time unavailable; renewal decision refused",
                               HTTPD_RESP_USE_STRLEN);
    }

    const int64_t seconds_remaining = expires - now;
    if (seconds_remaining > 30LL * 86400LL) {
        char response[256];
        const int64_t days_remaining = seconds_remaining / 86400LL;
        const int length = snprintf(response, sizeof(response),
            "{\"renewed\":false,\"reason\":\"not_due\",\"days_remaining\":%" PRId64 ","
            "\"renew_before_days\":30,\"automatic_renewal\":false}\n", days_remaining);
        if (length < 0 || length >= (int)sizeof(response))
            return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
        httpd_resp_set_status(request, "409 Conflict");
        httpd_resp_set_type(request, "application/json");
        set_security_headers(request);
        return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    }

    /* Renewal is deliberately manual and reuses the existing production issuance path.
     * That path creates a fresh P-256 certificate key and only stores material after
     * the returned certificate has passed SAN/private-key validation. It does not
     * activate the new certificate for management TLS. */
    return production_certificate_issue_for_hostname(request, status.hostname);
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
        "\"leaf_sha256\":\"%s\",\"active_management_tls_changed\":%s,"
        "\"active_tls_source\":\"%s\"}\n",
        status.hostname,
        status.key_present ? "true" : "false",
        status.certificate_present ? "true" : "false",
        status.hostname_present ? "true" : "false",
        status.certificate_parse_valid ? "true" : "false",
        status.hostname_matches_certificate ? "true" : "false",
        status.private_key_matches_certificate ? "true" : "false",
        status.chain_certificate_count,
        (unsigned)status.certificate_pem_length,
        status.valid_from, status.valid_to, status.leaf_sha256,
        s_tls_source != WEB_TLS_EMBEDDED ? "true" : "false",
        tls_source_name(s_tls_source));
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    if (err == ESP_ERR_INVALID_STATE) httpd_resp_set_status(request, "409 Conflict");
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_production_certificate_inspection_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t status;
    const esp_err_t err = acme_client_inspect_stored_production_certificate(&status);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "404 Not Found");
        httpd_resp_set_type(request, "application/json");
        set_security_headers(request);
        return httpd_resp_send(request,
                               "{\"stored\":false,\"environment\":\"production\",\"active_management_tls_changed\":false,\"active_tls_source\":\"embedded_development\"}\n",
                               HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Stored production certificate inspection failed: %s", esp_err_to_name(err));
        httpd_resp_set_status(request, "500 Internal Server Error");
        return httpd_resp_send(request, "Stored production certificate inspection failed", HTTPD_RESP_USE_STRLEN);
    }

    char active_slot = '?';
    bool slot_a_valid = false, slot_b_valid = false, legacy_material_present = false;
    const esp_err_t storage_err = acme_client_get_production_storage_status(
        &active_slot, &slot_a_valid, &slot_b_valid, &legacy_material_present);
    if (storage_err != ESP_OK) {
        ESP_LOGE(TAG, "Production dual-slot status failed: %s", esp_err_to_name(storage_err));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Production dual-slot status failed");
    }

    char response[1280];
    const int length = snprintf(response, sizeof(response),
        "{\"stored\":true,\"environment\":\"production\",\"hostname\":\"%s\","
        "\"key_present\":%s,\"certificate_present\":%s,\"hostname_present\":%s,"
        "\"certificate_parse_valid\":%s,\"hostname_matches_certificate\":%s,"
        "\"private_key_matches_certificate\":%s,\"chain_certificate_count\":%u,"
        "\"pem_length\":%u,\"valid_from\":\"%s\",\"valid_to\":\"%s\","
        "\"leaf_sha256\":\"%s\",\"production_storage\":{\"mode\":\"dual_slot\","
        "\"active_slot\":\"%c\",\"slot_a_valid\":%s,\"slot_b_valid\":%s,"
        "\"legacy_material_present\":%s},\"active_management_tls_changed\":%s,"
        "\"active_tls_source\":\"%s\"}\n",
        status.hostname,
        status.key_present ? "true" : "false",
        status.certificate_present ? "true" : "false",
        status.hostname_present ? "true" : "false",
        status.certificate_parse_valid ? "true" : "false",
        status.hostname_matches_certificate ? "true" : "false",
        status.private_key_matches_certificate ? "true" : "false",
        status.chain_certificate_count,
        (unsigned)status.certificate_pem_length,
        status.valid_from, status.valid_to, status.leaf_sha256,
        active_slot,
        slot_a_valid ? "true" : "false",
        slot_b_valid ? "true" : "false",
        legacy_material_present ? "true" : "false",
        s_tls_source != WEB_TLS_EMBEDDED ? "true" : "false",
        tls_source_name(s_tls_source));
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    if (err == ESP_ERR_INVALID_STATE) httpd_resp_set_status(request, "409 Conflict");
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}


static esp_err_t acme_production_certificate_lifecycle_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t status;
    const esp_err_t err = acme_client_inspect_stored_production_certificate(&status);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "404 Not Found");
        httpd_resp_set_type(request, "application/json");
        set_security_headers(request);
        return httpd_resp_send(request,
            "{\"stored\":false,\"environment\":\"production\",\"renewal_policy\":{\"mode\":\"manual\",\"renew_before_days\":30,\"urgent_before_days\":7,\"automatic_renewal\":false}}\n",
            HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "Production certificate inspection failed");

    int64_t now = 0, expires = 0;
    const bool now_valid = get_current_unix_time(&now);
    const bool expiry_valid = parse_utc_timestamp(status.valid_to, &expires);
    int64_t seconds_remaining = 0;
    int64_t days_remaining = 0;
    const char *state = "time_unavailable";
    bool renewal_due = false;
    bool urgent = false;
    bool expired = false;

    if (now_valid && expiry_valid) {
        seconds_remaining = expires - now;
        days_remaining = seconds_remaining >= 0 ? seconds_remaining / 86400LL : -((-seconds_remaining + 86399LL) / 86400LL);
        expired = seconds_remaining <= 0;
        urgent = !expired && seconds_remaining <= 7LL * 86400LL;
        renewal_due = !expired && seconds_remaining <= 30LL * 86400LL;
        state = expired ? "expired" : (urgent ? "urgent" : (renewal_due ? "renewal_due" : "valid"));
    }

    char response[1400];
    const int length = snprintf(response, sizeof(response),
        "{\"stored\":true,\"environment\":\"production\",\"hostname\":\"%s\"," 
        "\"certificate_valid\":%s,\"valid_from\":\"%s\",\"valid_to\":\"%s\"," 
        "\"clock_now_valid\":%s,\"unix_time\":%" PRId64 ",\"expiry_unix_time\":%" PRId64 ","
        "\"seconds_remaining\":%" PRId64 ",\"days_remaining\":%" PRId64 ","
        "\"lifecycle_state\":\"%s\",\"renewal_due\":%s,\"urgent\":%s,\"expired\":%s,"
        "\"renewal_policy\":{\"mode\":\"manual\",\"renew_before_days\":30,\"urgent_before_days\":7,"
        "\"automatic_renewal\":false,\"private_key_exportable\":false,\"acme_account_key_exportable\":false},"
        "\"active_tls_source\":\"%s\"}\n",
        status.hostname,
        (status.certificate_parse_valid && status.hostname_matches_certificate && status.private_key_matches_certificate) ? "true" : "false",
        status.valid_from, status.valid_to,
        now_valid ? "true" : "false", now_valid ? now : 0,
        expiry_valid ? expires : 0, seconds_remaining, days_remaining, state,
        renewal_due ? "true" : "false", urgent ? "true" : "false", expired ? "true" : "false",
        tls_source_name(s_tls_source));
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_production_certificate_export_handler(httpd_req_t *request)
{
    char *pem = NULL;
    size_t pem_length = 0U;
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    const esp_err_t err = acme_client_load_production_certificate_pem(&pem, &pem_length,
                                                                      hostname, sizeof(hostname));
    if (err == ESP_ERR_NOT_FOUND) {
        return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "Production certificate not stored");
    }
    if (err != ESP_OK || pem == NULL) {
        ESP_LOGE(TAG, "Production certificate export failed: %s", esp_err_to_name(err));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "Production certificate export failed");
    }

    httpd_resp_set_type(request, "application/x-pem-file");
    httpd_resp_set_hdr(request, "Content-Disposition", "attachment; filename=production-chain.pem");
    httpd_resp_set_hdr(request, "X-Private-Key-Exportable", "false");
    httpd_resp_set_hdr(request, "X-ACME-Account-Key-Exportable", "false");
    httpd_resp_set_hdr(request, "X-Certificate-Private-Key-Policy", "non-exportable");
    set_security_headers(request);
    const esp_err_t send_err = httpd_resp_send(request, pem, (ssize_t)pem_length);
    memset(pem, 0, pem_length + 1U);
    free(pem);
    return send_err;
}

static bool tls_transition_try_claim(void)
{
    bool claimed = false;
    taskENTER_CRITICAL(&s_tls_transition_lock);
    if (!s_tls_transition_pending) {
        s_tls_transition_pending = true;
        claimed = true;
    }
    taskEXIT_CRITICAL(&s_tls_transition_lock);
    return claimed;
}

static void tls_transition_release(void)
{
    taskENTER_CRITICAL(&s_tls_transition_lock);
    s_tls_transition_pending = false;
    taskEXIT_CRITICAL(&s_tls_transition_lock);
}

static esp_err_t acme_certificate_activate_test_handler(httpd_req_t *request)
{
    if (s_tls_source == WEB_TLS_STORED_TEST) {
        httpd_resp_set_type(request, "application/json"); set_security_headers(request);
        return httpd_resp_send(request, "{\"scheduled\":false,\"active_tls_source\":\"stored_staging_test\"}\n", HTTPD_RESP_USE_STRLEN);
    }
    acme_certificate_inspection_t inspection;
    const esp_err_t inspect_err = acme_client_inspect_stored_certificate(&inspection);
    if (inspect_err != ESP_OK || !inspection.certificate_parse_valid ||
        !inspection.hostname_matches_certificate || !inspection.private_key_matches_certificate) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Stored certificate is not eligible for test activation", HTTPD_RESP_USE_STRLEN);
    }
    if (!tls_transition_try_claim()) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "TLS transition already pending", HTTPD_RESP_USE_STRLEN);
    }
    if (xTaskCreate(tls_transition_task, "tls_switch", 8192U,
                    (void *)(uintptr_t)WEB_TLS_STORED_TEST, 5U, NULL) != pdPASS) {
        tls_transition_release();
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to schedule TLS transition");
    }
    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request,
        "{\"scheduled\":true,\"target_tls_source\":\"stored_staging_test\",\"persistent\":false,\"management_client_ca_unchanged\":true}\n",
        HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_production_certificate_activate_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t inspection;
    const esp_err_t inspect_err = acme_client_inspect_stored_production_certificate(&inspection);
    if (inspect_err != ESP_OK || !inspection.certificate_parse_valid ||
        !inspection.hostname_matches_certificate || !inspection.private_key_matches_certificate) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Production certificate is not eligible for activation", HTTPD_RESP_USE_STRLEN);
    }
    if (s_tls_source == WEB_TLS_PRODUCTION) {
        esp_err_t err = acme_client_set_production_boot_selected(true);
        if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to persist production TLS boot selection");
        httpd_resp_set_type(request, "application/json"); set_security_headers(request);
        return httpd_resp_send(request, "{\"scheduled\":false,\"active_tls_source\":\"stored_production\",\"persistent\":true}\n", HTTPD_RESP_USE_STRLEN);
    }
    if (!tls_transition_try_claim()) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "TLS transition already pending", HTTPD_RESP_USE_STRLEN);
    }
    if (xTaskCreate(tls_transition_task, "tls_prod", 8192U,
                    (void *)(uintptr_t)WEB_TLS_PRODUCTION, 5U, NULL) != pdPASS) {
        tls_transition_release();
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to schedule production TLS activation");
    }
    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request,
        "{\"scheduled\":true,\"target_tls_source\":\"stored_production\",\"persistent\":true,\"management_client_ca_unchanged\":true}\n",
        HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_certificate_rollback_handler(httpd_req_t *request)
{
    if (s_tls_source == WEB_TLS_EMBEDDED) {
        const esp_err_t pref_err = acme_client_set_production_boot_selected(false);
        if (pref_err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to persist embedded TLS boot selection");
        httpd_resp_set_type(request, "application/json"); set_security_headers(request);
        return httpd_resp_send(request, "{\"scheduled\":false,\"active_tls_source\":\"embedded_development\",\"persistent\":true}\n", HTTPD_RESP_USE_STRLEN);
    }
    if (!tls_transition_try_claim()) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "TLS transition already pending", HTTPD_RESP_USE_STRLEN);
    }
    if (xTaskCreate(tls_transition_task, "tls_rollback", 8192U,
                    (void *)(uintptr_t)WEB_TLS_EMBEDDED, 5U, NULL) != pdPASS) {
        tls_transition_release();
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to schedule TLS rollback");
    }
    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request,
        "{\"scheduled\":true,\"target_tls_source\":\"embedded_development\",\"management_client_ca_unchanged\":true}\n",
        HTTPD_RESP_USE_STRLEN);
}


static void delayed_reboot_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(1200U));
    esp_restart();
}

static esp_err_t system_reboot_handler(httpd_req_t *request)
{
    if (xTaskCreate(delayed_reboot_task, "web_reboot", 2048U,
                    NULL, 5U, NULL) != pdPASS) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "unable to schedule reboot");
    }

    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request,
                           "{\"scheduled\":true,\"action\":\"reboot\"}\n",
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t index_handler(httpd_req_t *request)
{
    static const char html[] =
        "<!doctype html>\n"
        "<html lang=\"en\"><head>\n"
        "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        "<title>ESP32-P4 NTP Console</title>\n"
        "<style>\n"
        ":root{color-scheme:dark}*{box-sizing:border-box}\n"
        "body{margin:0;background:#0d141b;color:#e9f0f5;font-family:Arial,sans-serif}\n"
        "header{padding:22px 28px;background:#14212d;border-bottom:1px solid #294252}\n"
        ".headerline{display:flex;align-items:center;gap:20px}.headertitle{min-width:max-content}.headerstatus{display:flex;justify-content:center;gap:10px;flex-wrap:wrap;flex:1;margin-left:auto}\n"
        "h1{margin:0;color:#58c7ff;font-size:1.55rem}header p{margin:7px 0 0;color:#a8bac7;font-size:.92rem}\n"
        "main{padding:22px;max-width:1500px;margin:auto;overflow:hidden}\n"
        ".summary{display:flex;gap:10px;flex-wrap:wrap}\n"
        ".badge{padding:8px 12px;border-radius:999px;font-weight:bold;font-size:.82rem}\n"
        ".ok{background:#173f2b;color:#9bea75}.warn{background:#493b18;color:#ffd569}\n"
        ".bad{background:#4c2226;color:#ff9292}.neutral{background:#223643;color:#a9d8ef}\n"
        ".cardcolumns{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;align-items:start}.cardcol{display:flex;flex-direction:column;gap:16px;min-width:0}\n"
        ".card{background:#14212d;border:1px solid #294252;border-radius:10px;padding:17px;min-width:0;max-width:100%;overflow:hidden}\n"
        ".card h2{margin:0 0 13px;color:#8fdb75;font-size:1.02rem}\n"
        ".row{display:grid;grid-template-columns:minmax(0,44%) minmax(0,56%);gap:14px;padding:9px 0;border-bottom:1px solid #203440;align-items:start}\n"
        ".row:last-child{border-bottom:0}.key{color:#9eb2c0;line-height:1.35;min-width:0}\n"
        ".value{font-family:ui-monospace,Consolas,monospace;text-align:right;line-height:1.35;min-width:0;max-width:100%;overflow-wrap:anywhere;word-break:break-word;white-space:normal}.nowrap{white-space:nowrap;overflow-wrap:normal;word-break:normal;font-size:clamp(.72rem,.85vw,.92rem)}\n"
        ".actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}\n"
        "button{border:1px solid #3d6175;background:#203b4b;color:#e9f0f5;border-radius:7px;padding:10px 14px;font-weight:bold;cursor:pointer}\n"
        "button:hover{background:#294d61}button.danger{border-color:#81434a;background:#4c2226}button:disabled{opacity:.55;cursor:not-allowed}\n"
        ".actionmsg{margin-top:12px;color:#a8bac7;overflow-wrap:anywhere}\n"
        "footer{padding:22px 0 4px;color:#8ca1ae;font-size:.82rem}code{color:#9bea75;overflow-wrap:anywhere}\n"
        "@media(max-width:1200px){.cardcolumns{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:700px){.cardcolumns{grid-template-columns:1fr}main{padding:12px}.row{grid-template-columns:1fr;gap:4px}.value{text-align:left}header{padding:18px}.headerline{align-items:flex-start;flex-direction:column}.headerstatus{justify-content:flex-start;margin-left:0}}\n"
        "</style></head><body>\n"
        "<header><div class=\"headerline\"><div class=\"headertitle\"><h1>ESP32-P4 GNSS NTP Server</h1>\n"
        "<p>mTLS-authenticated HTTPS operational console &middot; automatic refresh every three seconds</p></div>\n"
        "<div class=\"headerstatus\" id=\"summary\"></div></div></header>\n"
        "<main><div id=\"cards\"></div>\n"
        "</main>\n"
        "<script>\n"
        "function esc(v){return String(v==null||v===''?'--':v).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}\n"
        "function row(k,v){return '<div class=\"row\"><span class=\"key\">'+esc(k)+'</span><span class=\"value\">'+esc(v)+'</span></div>';}\n"
        "function rowNowrap(k,v){return '<div class=\"row\"><span class=\"key\">'+esc(k)+'</span><span class=\"value nowrap\">'+esc(v)+'</span></div>';}\n"
        "function card(t,r,extra=''){return '<section class=\"card\"><h2>'+esc(t)+'</h2>'+r.join('')+extra+'</section>';}\n"
        "function badge(t,c){return '<span class=\"badge '+c+'\">'+esc(t)+'</span>';}\n"
        "function yesNo(v){return v?'YES':'NO';}\n"
        "function utc(v,valid=true){if(!valid||!v)return '--';try{return new Date(Number(v)*1000).toISOString();}catch(e){return '--';}}\n"
        "function hst(v,valid=true){if(!valid||!v)return '--';try{const d=new Date((Number(v)-36000)*1000);const p=n=>String(n).padStart(2,'0');return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds())+' HST';}catch(e){return '--';}}\n"
        "function duration(v){v=Math.max(0,Math.floor(Number(v)||0));const d=Math.floor(v/86400);v%=86400;const h=Math.floor(v/3600);v%=3600;const m=Math.floor(v/60);const sec=v%60;return (d?d+'d ':'')+String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0');}\n"
        "function stateClass(s){if(s==='SYNCHRONIZED'||s==='valid')return'ok';if(s==='HOLDOVER'||s==='ACQUIRING'||s==='renewal_due'||s==='urgent')return'warn';return'bad';}\n"
        "async function getJson(url){const r=await fetch(url,{cache:'no-store'});if(!r.ok)throw new Error(url+' HTTP '+r.status);return r.json();}\n"
        "async function action(url,label){\n"
        " const b=document.getElementById(label);if(b)b.disabled=true;\n"
        " const m=document.getElementById('actionmsg');m.textContent='Working...';\n"
        " try{const r=await fetch(url,{method:'POST',cache:'no-store'});const t=await r.text();\n"
        " m.textContent=(r.ok?'Accepted: ':'Refused: ')+(t||('HTTP '+r.status));}\n"
        " catch(e){m.textContent='Request error: '+e.message;}\n"
        " if(b)b.disabled=false;\n"
        "}\n"
        "function renew(){if(confirm('Request production certificate renewal now? The existing 30-day renewal policy is still enforced.'))action('/api/v1/acme/production/certificate/renew','renewbtn');}\n"
        "function reboot(){if(confirm('Reboot the NTP server now? NTP and management HTTPS will be temporarily unavailable.'))action('/api/v1/system/reboot','rebootbtn');}\n"
        "async function refresh(){\n"
        " try{\n"
        "  const [d,cert,sched]=await Promise.all([\n"
        "   getJson('/api/v1/status'),\n"
        "   getJson('/api/v1/acme/production/certificate'),\n"
        "   getJson('/api/v1/acme/production/renewal/scheduler')\n"
        "  ]);\n"
        "  const summary=[\n"
        "   badge('Clock: '+d.clock.state,stateClass(d.clock.state)),\n"
        "   badge('NTP: '+(d.readiness.ntp_ready?'READY':'NOT READY'),d.readiness.ntp_ready?'ok':'bad'),\n"
        "   badge('GNSS: '+(d.gnss.receiver_model||'IDENTITY PENDING'),d.gnss.receiver_identity_valid?'ok':'warn'),\n"
        "   badge('Certificate: '+(cert.certificate_parse_valid?'VALID':'INVALID'),cert.certificate_parse_valid?'ok':'bad'),\n"
        "   badge('Renewal: '+sched.state,stateClass(sched.state))\n"
        "  ];\n"
        "  document.getElementById('summary').innerHTML=summary.join('');\n"
        "  const col1=[]; const col2=[]; const col3=[]; const col4=[];\n"
        "  const certValid=cert.certificate_parse_valid&&cert.hostname_matches_certificate&&cert.private_key_matches_certificate;\n"
        "  col1.push(card('Clock and Time',[\n"
        "   row('State',d.clock.state),row('Disciplined',yesNo(d.clock.solution_valid)),\n"
        "   row('UTC Time',utc(d.readiness.unix_time,d.readiness.clock_now_valid)),\n"
        "   row('Phase Error',d.clock.phase_error_ns+' ns'),row('Frequency',d.clock.frequency_ppm+' ppm'),\n"
        "   row('Samples',d.clock.accepted_samples+' accepted / '+d.clock.rejected_samples+' rejected'),\n"
        "   row('Holdover',d.clock.holdover_seconds+' s')]));\n"
        "  col2.push(card('PPS Capture',[\n"
        "   row('Interval Valid',yesNo(d.pps.valid)),row('Period',d.pps.period_us+' us'),\n"
        "   row('Jitter',d.pps.jitter_us+' us'),row('Last Edge Age',d.pps.age_us+' us'),\n"
        "   row('Captured Edges',d.pps.edge_count),row('Queue Drops',d.pps.queue_drops)]));\n"
        "  col3.push(card('GNSS Receiver',[\n"
        "   row('Receiver Model',d.gnss.receiver_model),\n"
        "   row('Receiver SW',d.gnss.receiver_software_version),\n"
        "   row('Receiver HW',d.gnss.receiver_hardware_version),\n"
        "   row('Identity From UBX',yesNo(d.gnss.receiver_identity_valid)),\n"
        "   row('UTC Valid',yesNo(d.gnss.utc_valid)),row('Fix Valid',yesNo(d.gnss.fix_valid)),\n"
        "   row('Fix Type',d.gnss.fix_type),row('Satellites',d.gnss.satellites),\n"
        "   row('Time Fully Resolved',yesNo(d.gnss.fully_resolved)),\n"
        "   row('Leap State',d.gnss.leap),row('Current Leap Offset',d.gnss.current_leap_seconds+' s'),\n"
        "   row('TIM-TP qErr',d.gnss.timing_qerr_ps+' ps')]));\n"
        "  col4.push(card('Certificate & ACME',[\n"
        "   row('Certificate Valid',yesNo(certValid)),rowNowrap('Hostname',cert.hostname),\n"
        "   row('Valid From',cert.valid_from),row('Valid To',cert.valid_to),\n"
        "   row('Days Remaining',sched.days_remaining),row('Renew Before','30 days'),\n"
        "   row('Scheduler State',sched.state),row('Automatic Renewal',yesNo(sched.automatic_renewal_enabled)),\n"
        "   row('Automatic TLS Activation',yesNo(sched.automatic_tls_activation)),\n"
        "   row('Last Renewal Attempt',utc(sched.last_attempt_unix,sched.last_attempt_unix>0)),\n"
        "   row('Last Attempt Result',sched.last_attempt_result_valid?sched.last_attempt_result:'none'),\n"
        "   row('Last TLS Activation',utc(sched.tls_activation_last_completed_unix,sched.tls_activation_last_result_valid)),\n"
        "   row('Active Slot',cert.production_storage?cert.production_storage.active_slot:'--'),\n"
        "   row('Slot A Valid',cert.production_storage?yesNo(cert.production_storage.slot_a_valid):'--'),\n"
        "   row('Slot B Valid',cert.production_storage?yesNo(cert.production_storage.slot_b_valid):'--'),\n"
        "   row('Leaf SHA-256',cert.leaf_sha256),\n"
        "   row('Running SHA-256',sched.tls_current_leaf_sha256),\n"
        "   row('Activation Intent Pending',yesNo(sched.tls_activation_intent_pending)),\n"
        "   row('Handoff In Progress',yesNo(sched.tls_handoff_in_progress))\n"
        "  ]));\n"
        "  col1.push(card('NTP Service',[\n"
        "   row('UDP Socket Bound',yesNo(d.ntp.socket_bound)),row('Advertised Stratum',d.ntp.advertised_stratum),\n"
        "   row('Leap Indicator',d.ntp.advertised_leap),row('Requests Received',d.ntp.requests),\n"
        "   row('Responses Sent',d.ntp.responses),row('Invalid Requests',d.ntp.invalid_requests),\n"
        "   row('Fail-Closed Drops',d.ntp.unsynchronized_drops),row('RATE KoD Responses',d.ntp.rate_kod),\n"
        "   row('Last Client',d.ntp.last_client)]));\n"
        "  col2.push(card('NTS Service',[\n"
        "   row('NTS-KE Running',yesNo(d.nts.ke_running)),row('NTS-KE Exchanges',d.nts.ke_exchanges),\n"
        "   row('NTS-KE Failures',d.nts.ke_exchange_failures),row('TLS Handshake Failures',d.nts.ke_tls_handshake_failures),\n"
        "   row('ALPN Rejections',d.nts.ke_alpn_rejections),row('Verification Attempts',d.nts.verification_attempts),\n"
        "   row('Authenticated Requests',d.nts.authenticated_requests),row('Verification Failures',d.nts.verification_failures),\n"
        "   row('Protected Responses',d.nts.protected_responses),row('Protection Failures',d.nts.protection_failures)]));\n"        "  col2.push(card('API Locations',[\n"
        "   row('Status','/api/v1/status'),row('Health','/api/v1/health'),row('Metrics','/metrics'),\n"
        "   row('Configuration','GET /api/v1/config'),row('Hostname','PUT /api/v1/config/hostname'),\n"
        "   row('Cloudflare','PUT/DELETE /api/v1/config/cloudflare')]));\n"
        "  col3.push(card('Network',[\n"
        "   row('Hostname',d.device.hostname),row('IPv4 Address',d.device.ipv4),row('Netmask',d.device.netmask),\n"
        "   row('Gateway',d.device.gateway),row('Ethernet Link',yesNo(d.device.link_up)),row('Ethernet MAC',d.device.mac)]));\n"
        "  col1.push(card('System Actions',[\n"
        "   row('Uptime',duration(d.system.uptime_seconds)),row('Last Reset',hst(d.system.boot_time_unix,d.system.boot_time_valid)),\n"
        "   row('Reset Reason',d.system.reset_reason),row('Management TLS',d.console.mode),row('Renewal Eligible Now',yesNo(sched.eligible))\n"
        "  ],'<div class=\"actions\"><button id=\"renewbtn\" onclick=\"renew()\">Renew Certificate</button><button id=\"rebootbtn\" class=\"danger\" onclick=\"reboot()\">Reboot Device</button></div><div id=\"actionmsg\" class=\"actionmsg\">Actions require this authenticated mTLS session.</div>'));\n"
        "  document.getElementById('cards').innerHTML='<div class=\"cardcolumns\"><div class=\"cardcol\">'+col1.join('')+'</div><div class=\"cardcol\">'+col2.join('')+'</div><div class=\"cardcol\">'+col3.join('')+'</div><div class=\"cardcol\">'+col4.join('')+'</div></div>';\n"
        " }catch(e){\n"
        "  document.getElementById('summary').innerHTML=badge('Console: STATUS UNAVAILABLE','bad');\n"
        "  document.getElementById('cards').innerHTML='<section class=\"card\"><h2>Console Error</h2><p>'+esc(e.message)+'</p></section>';\n"
        " }\n"
        "}\n"
        "refresh();setInterval(refresh,3000);\n"
        "</script></body></html>\n";

    httpd_resp_set_type(request, "text/html");
    set_security_headers(request);
    return httpd_resp_send(request, html, HTTPD_RESP_USE_STRLEN);
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

static const httpd_uri_t s_system_reboot_uri = {
    .uri = "/api/v1/system/reboot",
    .method = HTTP_POST,
    .handler = system_reboot_handler,
    .user_ctx = NULL,
};

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



static const httpd_uri_t s_acme_production_certificate_issue_uri = {
    .uri = "/api/v1/acme/production/certificate/issue",
    .method = HTTP_POST,
    .handler = acme_production_certificate_issue_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_certificate_renew_uri = {
    .uri = "/api/v1/acme/production/certificate/renew",
    .method = HTTP_POST,
    .handler = acme_production_certificate_renew_handler,
    .user_ctx = NULL,
};


static const httpd_uri_t s_acme_certificate_inspection_uri = {
    .uri = "/api/v1/acme/certificate",
    .method = HTTP_GET,
    .handler = acme_certificate_inspection_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_certificate_inspection_uri = {
    .uri = "/api/v1/acme/production/certificate",
    .method = HTTP_GET,
    .handler = acme_production_certificate_inspection_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_certificate_lifecycle_uri = {
    .uri = "/api/v1/acme/production/certificate/lifecycle",
    .method = HTTP_GET,
    .handler = acme_production_certificate_lifecycle_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_renewal_scheduler_uri = {
    .uri = "/api/v1/acme/production/renewal/scheduler",
    .method = HTTP_GET,
    .handler = acme_production_renewal_scheduler_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_renewal_scheduler_put_uri = {
    .uri = "/api/v1/acme/production/renewal/scheduler",
    .method = HTTP_PUT,
    .handler = acme_production_renewal_scheduler_put_handler,
    .user_ctx = NULL,
};




static const httpd_uri_t s_acme_production_certificate_export_uri = {
    .uri = "/api/v1/acme/production/certificate/export",
    .method = HTTP_GET,
    .handler = acme_production_certificate_export_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_certificate_activate_test_uri = {
    .uri = "/api/v1/acme/certificate/activate-test",
    .method = HTTP_POST,
    .handler = acme_certificate_activate_test_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_certificate_activate_uri = {
    .uri = "/api/v1/acme/production/certificate/activate",
    .method = HTTP_POST,
    .handler = acme_production_certificate_activate_handler,
};

static const httpd_uri_t s_acme_certificate_rollback_uri = {
    .uri = "/api/v1/acme/certificate/rollback",
    .method = HTTP_POST,
    .handler = acme_certificate_rollback_handler,
    .user_ctx = NULL,
};

static esp_err_t register_all_handlers(httpd_handle_t server)
{
    const httpd_uri_t *handlers[] = {
        &s_index_uri, &s_status_uri, &s_health_uri, &s_metrics_uri,
        &s_system_reboot_uri,
        &s_config_get_uri, &s_hostname_put_uri, &s_cloudflare_put_uri,
        &s_cloudflare_delete_uri, &s_cloudflare_verify_uri,
        &s_dns01_create_uri, &s_dns01_query_uri, &s_dns01_delete_uri,
        &s_acme_staging_probe_uri, &s_acme_account_status_uri,
        &s_acme_account_provision_uri, &s_acme_staging_order_discover_uri,
        &s_acme_staging_dns01_validate_uri, &s_acme_staging_certificate_issue_uri,
        &s_acme_production_certificate_issue_uri, &s_acme_production_certificate_renew_uri,
        &s_acme_certificate_inspection_uri,
        &s_acme_production_certificate_inspection_uri, &s_acme_production_certificate_lifecycle_uri,
        &s_acme_production_renewal_scheduler_uri, &s_acme_production_renewal_scheduler_put_uri,
        &s_acme_production_certificate_export_uri,
        &s_acme_certificate_activate_test_uri,
        &s_acme_production_certificate_activate_uri,
        &s_acme_certificate_rollback_uri,
    };
    for (size_t i = 0U; i < sizeof(handlers) / sizeof(handlers[0]); ++i) {
        const esp_err_t err = httpd_register_uri_handler(server, handlers[i]);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}

static esp_err_t start_https_server(web_tls_source_t source)
{
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    acme_tls_credentials_t candidate;
    memset(&candidate, 0, sizeof(candidate));

    config.httpd.stack_size = APP_WEB_CONSOLE_STACK_SIZE;
    config.httpd.max_uri_handlers = APP_WEB_CONSOLE_MAX_HANDLERS;
    config.httpd.max_open_sockets = APP_WEB_CONSOLE_MAX_OPEN_SOCKETS;
    config.httpd.lru_purge_enable = true;
    config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    config.port_secure = APP_WEB_CONSOLE_PORT;
    config.cacert_pem = management_ca_pem_start;
    config.cacert_len = (size_t)(management_ca_pem_end - management_ca_pem_start);

    if (source == WEB_TLS_STORED_TEST || source == WEB_TLS_PRODUCTION) {
        esp_err_t err = source == WEB_TLS_PRODUCTION
                            ? acme_client_load_production_tls_credentials(&candidate)
                            : acme_client_load_stored_tls_credentials(&candidate);
        if (err != ESP_OK) return err;
        config.servercert = (const uint8_t *)candidate.certificate_pem;
        config.servercert_len = candidate.certificate_pem_length;
        config.prvtkey_pem = (const uint8_t *)candidate.private_key_pem;
        config.prvtkey_len = candidate.private_key_pem_length;
    } else {
        config.servercert = servercert_pem_start;
        config.servercert_len = (size_t)(servercert_pem_end - servercert_pem_start);
        config.prvtkey_pem = serverkey_pem_start;
        config.prvtkey_len = (size_t)(serverkey_pem_end - serverkey_pem_start);
    }

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_ssl_start(&server, &config);
    if (err == ESP_OK) err = register_all_handlers(server);
    if (err != ESP_OK) {
        if (server != NULL) (void)httpd_ssl_stop(server);
        acme_client_free_tls_credentials(&candidate);
        return err;
    }

    s_server = server;
    s_started = true;
    s_tls_source = source;
    memset(s_active_server_leaf_sha256, 0, sizeof(s_active_server_leaf_sha256));
    if (source == WEB_TLS_PRODUCTION) {
        acme_certificate_inspection_t active_inspection;
        if (acme_client_inspect_stored_production_certificate(&active_inspection) == ESP_OK) {
            snprintf(s_active_server_leaf_sha256, sizeof(s_active_server_leaf_sha256),
                     "%s", active_inspection.leaf_sha256);
        }
    }
    if (source == WEB_TLS_STORED_TEST || source == WEB_TLS_PRODUCTION) {
        s_active_stored_credentials = candidate;
        memset(&candidate, 0, sizeof(candidate));
    }
    ESP_LOGW(TAG, "mTLS management console active on TCP/%u; server credential=%s; client certificate required",
             APP_WEB_CONSOLE_PORT,
             tls_source_name(source));
    return ESP_OK;
}

static esp_err_t start_https_server_with_credentials(web_tls_source_t source,
                                                     acme_tls_credentials_t *credentials,
                                                     const char *known_leaf_sha256)
{
    if (source == WEB_TLS_EMBEDDED) return start_https_server(WEB_TLS_EMBEDDED);
    if (credentials == NULL || credentials->certificate_pem == NULL ||
        credentials->private_key_pem == NULL) return ESP_ERR_INVALID_ARG;

    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.httpd.stack_size = APP_WEB_CONSOLE_STACK_SIZE;
    config.httpd.max_uri_handlers = APP_WEB_CONSOLE_MAX_HANDLERS;
    config.httpd.max_open_sockets = APP_WEB_CONSOLE_MAX_OPEN_SOCKETS;
    config.httpd.lru_purge_enable = true;
    config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    config.port_secure = APP_WEB_CONSOLE_PORT;
    config.cacert_pem = management_ca_pem_start;
    config.cacert_len = (size_t)(management_ca_pem_end - management_ca_pem_start);
    config.servercert = (const uint8_t *)credentials->certificate_pem;
    config.servercert_len = credentials->certificate_pem_length;
    config.prvtkey_pem = (const uint8_t *)credentials->private_key_pem;
    config.prvtkey_len = credentials->private_key_pem_length;

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_ssl_start(&server, &config);
    if (err == ESP_OK) err = register_all_handlers(server);
    if (err != ESP_OK) {
        if (server != NULL) (void)httpd_ssl_stop(server);
        return err;
    }

    s_server = server;
    s_started = true;
    s_tls_source = source;
    s_active_stored_credentials = *credentials;
    memset(credentials, 0, sizeof(*credentials));
    memset(s_active_server_leaf_sha256, 0, sizeof(s_active_server_leaf_sha256));
    if (known_leaf_sha256 != NULL) {
        snprintf(s_active_server_leaf_sha256, sizeof(s_active_server_leaf_sha256), "%s", known_leaf_sha256);
    }
    ESP_LOGW(TAG, "mTLS management console restored on TCP/%u; server credential=%s; client certificate required",
             APP_WEB_CONSOLE_PORT, tls_source_name(source));
    return ESP_OK;
}

static void tls_transition_task(void *arg)
{
    const web_tls_source_t target = (web_tls_source_t)(uintptr_t)arg;
    const bool automatic_transition = s_tls_transition_automatic;
    const web_tls_source_t previous_source = s_tls_source;
    acme_tls_credentials_t previous_credentials;
    char previous_leaf_sha256[65];
    char automatic_target_leaf_sha256[65];
    memset(automatic_target_leaf_sha256, 0, sizeof(automatic_target_leaf_sha256));
    if (automatic_transition) {
        acme_tls_activation_intent_record_t intent_snapshot;
        if (acme_client_load_tls_activation_intent(&intent_snapshot) == ESP_OK && intent_snapshot.pending)
            snprintf(automatic_target_leaf_sha256, sizeof(automatic_target_leaf_sha256), "%s",
                     intent_snapshot.target_leaf_sha256);
    }
    memset(&previous_credentials, 0, sizeof(previous_credentials));
    snprintf(previous_leaf_sha256, sizeof(previous_leaf_sha256), "%s", s_active_server_leaf_sha256);

    vTaskDelay(pdMS_TO_TICKS(750));

    if (previous_source != WEB_TLS_EMBEDDED) {
        previous_credentials = s_active_stored_credentials;
        memset(&s_active_stored_credentials, 0, sizeof(s_active_stored_credentials));
    }
    if (s_server != NULL) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        s_started = false;
    }
    memset(s_active_server_leaf_sha256, 0, sizeof(s_active_server_leaf_sha256));

    esp_err_t err = start_https_server(target);
    if (err == ESP_OK) {
        if (target == WEB_TLS_PRODUCTION) {
            err = acme_client_set_production_boot_selected(true);
        } else if (target == WEB_TLS_EMBEDDED) {
            err = acme_client_set_production_boot_selected(false);
        }
    }

    if (err == ESP_OK) {
        acme_client_free_tls_credentials(&previous_credentials);
        if (target == WEB_TLS_PRODUCTION && s_active_server_leaf_sha256[0] != '\0') {
            acme_tls_activation_intent_record_t intent;
            const esp_err_t intent_load_err = acme_client_load_tls_activation_intent(&intent);
            if (intent_load_err == ESP_OK && intent.pending &&
                intent.target_leaf_sha256[0] != '\0' &&
                strcmp(intent.target_leaf_sha256, s_active_server_leaf_sha256) == 0) {
                const esp_err_t clear_err = tls_activation_intent_clear(false);
                if (clear_err == ESP_OK) {
                    portENTER_CRITICAL(&s_renewal_scheduler_lock);
                    snprintf(s_renewal_scheduler_status.tls_activation_reconciliation_result,
                             sizeof(s_renewal_scheduler_status.tls_activation_reconciliation_result),
                             "activated_runtime");
                    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
                } else {
                    ESP_LOGE(TAG, "TLS handoff succeeded but activation-intent clear failed: %s",
                             esp_err_to_name(clear_err));
                }
            }
        }
        if (target == WEB_TLS_PRODUCTION && automatic_transition) {
            const esp_err_t outcome_err = tls_activation_outcome_store(true, false, ESP_OK,
                                                                       automatic_target_leaf_sha256,
                                                                       s_active_server_leaf_sha256);
            if (outcome_err != ESP_OK)
                ESP_LOGE(TAG, "TLS activation succeeded but outcome persistence failed: %s", esp_err_to_name(outcome_err));
            int64_t handoff_done = 0; (void)get_current_unix_time(&handoff_done);
            const esp_err_t handoff_err = tls_handoff_finish(true, handoff_done);
            if (handoff_err != ESP_OK) ESP_LOGE(TAG, "TLS handoff success-state persistence failed: %s", esp_err_to_name(handoff_err));
        }
        ESP_LOGI(TAG, "TLS transition completed: %s -> %s",
                 tls_source_name(previous_source), tls_source_name(target));
    } else {
        ESP_LOGE(TAG, "TLS transition to %s failed: %s; restoring last-known-good %s credential",
                 tls_source_name(target), esp_err_to_name(err), tls_source_name(previous_source));

        if (s_server != NULL) {
            (void)httpd_ssl_stop(s_server);
            s_server = NULL;
            s_started = false;
        }
        if (s_tls_source != WEB_TLS_EMBEDDED) {
            acme_client_free_tls_credentials(&s_active_stored_credentials);
        }
        memset(s_active_server_leaf_sha256, 0, sizeof(s_active_server_leaf_sha256));

        esp_err_t rollback_err;
        if (previous_source == WEB_TLS_EMBEDDED) {
            rollback_err = start_https_server(WEB_TLS_EMBEDDED);
        } else {
            rollback_err = start_https_server_with_credentials(previous_source,
                                                               &previous_credentials,
                                                               previous_leaf_sha256);
        }

        if (rollback_err == ESP_OK) {
            const bool previous_production = previous_source == WEB_TLS_PRODUCTION;
            const esp_err_t pref_err = acme_client_set_production_boot_selected(previous_production);
            if (pref_err != ESP_OK) {
                ESP_LOGE(TAG, "Last-known-good TLS restored but boot preference restore failed: %s",
                         esp_err_to_name(pref_err));
            }
        } else {
            ESP_LOGE(TAG, "Last-known-good TLS restore failed: %s; attempting embedded emergency fallback",
                     esp_err_to_name(rollback_err));
            acme_client_free_tls_credentials(&previous_credentials);
            (void)acme_client_set_production_boot_selected(false);
            rollback_err = start_https_server(WEB_TLS_EMBEDDED);
            if (rollback_err != ESP_OK) {
                ESP_LOGE(TAG, "Management HTTPS emergency fallback failed: %s", esp_err_to_name(rollback_err));
            }
        }
        if (target == WEB_TLS_PRODUCTION && automatic_transition) {
            const bool lkg_restored = rollback_err == ESP_OK;
            const esp_err_t outcome_err = tls_activation_outcome_store(false, lkg_restored, err,
                                                                       automatic_target_leaf_sha256, s_active_server_leaf_sha256);
            if (outcome_err != ESP_OK)
                ESP_LOGE(TAG, "TLS activation failure outcome persistence failed: %s", esp_err_to_name(outcome_err));
            int64_t handoff_done = 0; (void)get_current_unix_time(&handoff_done);
            const esp_err_t handoff_err = tls_handoff_finish(false, handoff_done);
            if (handoff_err != ESP_OK) ESP_LOGE(TAG, "TLS handoff failure-state persistence failed: %s", esp_err_to_name(handoff_err));
        }
        acme_tls_activation_intent_record_t failed_intent;
        if (acme_client_load_tls_activation_intent(&failed_intent) == ESP_OK && failed_intent.pending) {
            portENTER_CRITICAL(&s_renewal_scheduler_lock);
            snprintf(s_renewal_scheduler_status.tls_activation_reconciliation_result,
                     sizeof(s_renewal_scheduler_status.tls_activation_reconciliation_result),
                     "activation_failed_lkg_restored");
            portEXIT_CRITICAL(&s_renewal_scheduler_lock);
        }
    }

    if (automatic_transition) s_tls_transition_automatic = false;
    tls_transition_release();
    vTaskDelete(NULL);
}

static esp_err_t web_console_start_https(void)
{
    if (s_started) return ESP_OK;
    esp_err_t err = acme_client_prepare_production_storage();
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGE(TAG, "Production credential store preparation failed: %s; using embedded credential",
                 esp_err_to_name(err));
        (void)acme_client_set_production_boot_selected(false);
        return start_https_server(WEB_TLS_EMBEDDED);
    }

    bool production_selected = false;
    err = acme_client_get_production_boot_selected(&production_selected);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "TLS boot selection read failed: %s; using embedded credential", esp_err_to_name(err));
        (void)acme_client_set_production_boot_selected(false);
        return start_https_server(WEB_TLS_EMBEDDED);
    }
    if (!production_selected) return start_https_server(WEB_TLS_EMBEDDED);

    err = start_https_server(WEB_TLS_PRODUCTION);
    if (err == ESP_OK) return ESP_OK;

    ESP_LOGE(TAG, "Production TLS boot failed: %s; clearing selection and falling back to embedded credential",
             esp_err_to_name(err));
    (void)acme_client_set_production_boot_selected(false);
    return start_https_server(WEB_TLS_EMBEDDED);
}

esp_err_t web_console_start(void)
{
    const esp_err_t err = web_console_start_https();
    if (err != ESP_OK) return err;

    const esp_err_t scheduler_err = start_renewal_scheduler();
    if (scheduler_err != ESP_OK) {
        ESP_LOGE(TAG, "ACME renewal scheduler start failed: %s", esp_err_to_name(scheduler_err));
        /* Management HTTPS remains available; scheduler failure never changes TLS/timing/NTP state. */
    }
    return ESP_OK;
}

bool web_console_is_running(void)
{
    return s_started;
}