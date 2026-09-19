#include "ntp_server.h"

#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "app_state.h"
#include "clock_discipline.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "ntp_packet.h"
#include "ntp_rate_limit.h"
#include "ntp_types.h"
#include "nts_ntp_auth.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/task.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"

#define APP_NTP_TASK_STACK_SIZE                 6144U
#define APP_NTP_TASK_PRIORITY                   12U
#define APP_NTP_RECEIVE_TIMEOUT_SECONDS         1U

static const char *TAG = "NTP";

static bool s_started;
static portMUX_TYPE s_ntp_lock = portMUX_INITIALIZER_UNLOCKED;
static ntp_server_status_t s_status;

static uint8_t s_request_buffer[NTS_NTP_MAX_PACKET_SIZE];
static uint8_t s_response_buffer[NTS_NTP_MAX_PACKET_SIZE];


typedef struct {
    uint64_t samples;
    uint64_t rx_start_sum_us;
    uint64_t rx_call_sum_us;
    uint64_t build_sum_us;
    uint64_t tx_to_send_sum_us;
    uint64_t send_call_sum_us;
    uint64_t total_sum_us;
} ntp_timing_sums_t;

static ntp_timing_sums_t s_timing_sums;
static int64_t s_hw_rx_delta_sum_ns;

static uint32_t clamp_duration_us(int64_t start_us, int64_t end_us)
{
    if (end_us <= start_us) {
        return 0U;
    }

    const uint64_t delta = (uint64_t)(end_us - start_us);
    return delta > UINT32_MAX ? UINT32_MAX : (uint32_t)delta;
}

static void update_min_max(uint32_t value,
                           uint32_t *minimum,
                           uint32_t *maximum,
                           uint64_t sample_number)
{
    if (sample_number == 1U || value < *minimum) {
        *minimum = value;
    }

    if (sample_number == 1U || value > *maximum) {
        *maximum = value;
    }
}

static void ntp_status_record_timing(uint32_t rx_start_us,
                                     uint32_t rx_call_us,
                                     uint32_t build_us,
                                     uint32_t tx_to_send_us,
                                     uint32_t send_call_us,
                                     uint32_t total_us)
{
    portENTER_CRITICAL(&s_ntp_lock);

    s_timing_sums.samples++;
    const uint64_t n = s_timing_sums.samples;

    s_timing_sums.rx_start_sum_us += rx_start_us;
    s_timing_sums.rx_call_sum_us += rx_call_us;
    s_timing_sums.build_sum_us += build_us;
    s_timing_sums.tx_to_send_sum_us += tx_to_send_us;
    s_timing_sums.send_call_sum_us += send_call_us;
    s_timing_sums.total_sum_us += total_us;

    s_status.timing_samples = n > UINT32_MAX ? UINT32_MAX : (uint32_t)n;

    s_status.rx_timestamp_start_avg_us = (uint32_t)(s_timing_sums.rx_start_sum_us / n);
    s_status.rx_timestamp_call_avg_us = (uint32_t)(s_timing_sums.rx_call_sum_us / n);
    s_status.response_build_avg_us = (uint32_t)(s_timing_sums.build_sum_us / n);
    s_status.tx_timestamp_to_send_avg_us = (uint32_t)(s_timing_sums.tx_to_send_sum_us / n);
    s_status.send_call_avg_us = (uint32_t)(s_timing_sums.send_call_sum_us / n);
    s_status.total_response_avg_us = (uint32_t)(s_timing_sums.total_sum_us / n);

    update_min_max(rx_start_us, &s_status.rx_timestamp_start_min_us,
                   &s_status.rx_timestamp_start_max_us, n);
    update_min_max(rx_call_us, &s_status.rx_timestamp_call_min_us,
                   &s_status.rx_timestamp_call_max_us, n);
    update_min_max(build_us, &s_status.response_build_min_us,
                   &s_status.response_build_max_us, n);
    update_min_max(tx_to_send_us, &s_status.tx_timestamp_to_send_min_us,
                   &s_status.tx_timestamp_to_send_max_us, n);
    update_min_max(send_call_us, &s_status.send_call_min_us,
                   &s_status.send_call_max_us, n);
    update_min_max(total_us, &s_status.total_response_min_us,
                   &s_status.total_response_max_us, n);

    portEXIT_CRITICAL(&s_ntp_lock);
}

static uint64_t ntp_timestamp_to_ns(ntp_timestamp_t timestamp)
{
    const uint64_t fractional_ns =
        (((uint64_t)timestamp.fraction * 1000000000ULL) + 0x80000000ULL) >> 32;
    return ((uint64_t)timestamp.seconds * 1000000000ULL) + fractional_ns;
}

static void ntp_status_record_hw_rx_comparison(
    ntp_timestamp_t software_rx,
    const eth_service_ntp_rx_timestamp_t *hardware_rx)
{
    if (hardware_rx == NULL) {
        return;
    }

    const ntp_timestamp_t hw = {
        .seconds = hardware_rx->seconds,
        .fraction = hardware_rx->fraction,
    };
    const int64_t delta_ns = (int64_t)ntp_timestamp_to_ns(software_rx) -
                             (int64_t)ntp_timestamp_to_ns(hw);

    portENTER_CRITICAL(&s_ntp_lock);
    s_status.hw_rx_compare_samples++;
    const uint32_t n = s_status.hw_rx_compare_samples;
    s_hw_rx_delta_sum_ns += delta_ns;
    s_status.hw_rx_delta_last_ns = delta_ns;
    s_status.hw_rx_delta_avg_ns = s_hw_rx_delta_sum_ns / (int64_t)n;
    if (n == 1U || delta_ns < s_status.hw_rx_delta_min_ns) {
        s_status.hw_rx_delta_min_ns = delta_ns;
    }
    if (n == 1U || delta_ns > s_status.hw_rx_delta_max_ns) {
        s_status.hw_rx_delta_max_ns = delta_ns;
    }
    s_status.hw_rx_mapping_bracket_last_ns = hardware_rx->mapping_bracket_ns;
    s_status.hw_rx_mapping_age_last_us = hardware_rx->mapping_age_us;
    const int64_t avg_ns = s_status.hw_rx_delta_avg_ns;
    const int64_t min_ns = s_status.hw_rx_delta_min_ns;
    const int64_t max_ns = s_status.hw_rx_delta_max_ns;
    portEXIT_CRITICAL(&s_ntp_lock);

    ESP_LOGI(TAG,
             "HW RX compare: n=%" PRIu32 " sw-hw=%" PRId64
             " ns min/avg/max=%" PRId64 "/%" PRId64 "/%" PRId64
             " ns map_bracket=%" PRIu32 " ns age=%" PRIu32 " us",
             n, delta_ns, min_ns, avg_ns, max_ns,
             hardware_rx->mapping_bracket_ns, hardware_rx->mapping_age_us);
}

static void ntp_status_record_hw_rx_miss(void)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.hw_rx_compare_misses++;
    portEXIT_CRITICAL(&s_ntp_lock);
}


static void ntp_status_record_hw_rx_authoritative(void)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.hw_rx_authoritative_responses++;
    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_record_hw_rx_authority_drop(void)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.hw_rx_authority_drops++;
    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_set_socket_bound(bool bound)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.socket_bound = bound;
    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_record_request(uint32_t client_ipv4)
{
    const int64_t now_us = esp_timer_get_time();

    portENTER_CRITICAL(&s_ntp_lock);

    s_status.requests_received++;
    s_status.last_client_ipv4 = client_ipv4;
    s_status.last_request_monotonic_us = now_us;

    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_record_invalid_request(void)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.invalid_requests++;
    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_record_unsynchronized_drop(void)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.unsynchronized_drops++;
    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_record_kod(void)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.rate_kod_responses++;
    s_status.last_response_monotonic_us = esp_timer_get_time();
    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_record_response(uint8_t stratum,
                                       uint8_t leap_indicator,
                                       uint32_t root_dispersion)
{
    portENTER_CRITICAL(&s_ntp_lock);

    s_status.normal_responses++;
    s_status.last_response_monotonic_us = esp_timer_get_time();

    s_status.advertised_stratum = stratum;
    s_status.advertised_leap_indicator = leap_indicator;
    s_status.advertised_root_dispersion = root_dispersion;

    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_record_send_failure(void)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.send_failures++;
    portEXIT_CRITICAL(&s_ntp_lock);
}

static void ntp_status_record_socket_failure(void)
{
    portENTER_CRITICAL(&s_ntp_lock);
    s_status.socket_open_failures++;
    portEXIT_CRITICAL(&s_ntp_lock);
}

static uint8_t leap_from_gnss(void)
{
    gnss_service_status_t gnss_status;

    if (!gnss_service_get_status(&gnss_status)) {
        return NTP_LI_UNSYNCED;
    }

    switch (gnss_status.leap_indicator) {
    case APP_LEAP_ADD_SECOND:
        return NTP_LI_ADD_SECOND;

    case APP_LEAP_DELETE_SECOND:
        return NTP_LI_DELETE_SECOND;

    case APP_LEAP_NO_WARNING:
        return NTP_LI_NO_WARNING;

    case APP_LEAP_UNKNOWN:
    default:
        return NTP_LI_UNSYNCED;
    }
}

static bool get_server_quality(uint8_t *out_stratum,
                               uint8_t *out_leap,
                               uint32_t *out_refid,
                               uint32_t *out_dispersion)
{
    if (out_stratum == NULL ||
        out_leap == NULL ||
        out_refid == NULL ||
        out_dispersion == NULL) {
        return false;
    }

    clock_discipline_status_t clock_status;

    if (!clock_discipline_get_status(&clock_status)) {
        return false;
    }

    if (clock_status.state == APP_CLOCK_SYNCHRONIZED &&
        clock_status.solution_valid) {
        const uint8_t leap = leap_from_gnss();

        if (leap == NTP_LI_UNSYNCED) {
            return false;
        }

        *out_stratum = NTP_STRATUM_PRIMARY;
        *out_leap = leap;
        *out_refid = ntp_packet_refid_from_text("GPS ");
        *out_dispersion = clock_status.root_dispersion_16_16;

        return true;
    }

    if (clock_status.state == APP_CLOCK_HOLDOVER &&
        clock_status.solution_valid) {
        *out_stratum = NTP_STRATUM_SECONDARY;
        *out_leap = NTP_LI_NO_WARNING;
        *out_refid = ntp_packet_refid_from_text("HOLD");
        *out_dispersion = clock_status.root_dispersion_16_16;

        return true;
    }

    return false;
}

static ntp_timestamp_t clock_to_ntp_timestamp(clock_ntp_timestamp_t timestamp)
{
    const ntp_timestamp_t result = {
        .seconds = timestamp.seconds,
        .fraction = timestamp.fraction,
    };

    return result;
}

static bool get_current_ntp_timestamp(ntp_timestamp_t *out_timestamp)
{
    if (out_timestamp == NULL) {
        return false;
    }

    clock_ntp_timestamp_t timestamp;

    if (!clock_discipline_get_ntp_timestamp(&timestamp)) {
        return false;
    }

    *out_timestamp = clock_to_ntp_timestamp(timestamp);

    return true;
}

static bool get_reference_ntp_timestamp(ntp_timestamp_t *out_timestamp)
{
    if (out_timestamp == NULL) {
        return false;
    }

    clock_ntp_timestamp_t timestamp;

    if (!clock_discipline_get_reference_timestamp(&timestamp, NULL)) {
        return false;
    }

    *out_timestamp = clock_to_ntp_timestamp(timestamp);

    return true;
}

static bool valid_client_request(const ntp_packet_fields_t *request)
{
    if (request == NULL) {
        return false;
    }

    if (request->mode != NTP_MODE_CLIENT) {
        return false;
    }

    /*
     * Preserve interoperability with legacy NTP/SNTP clients.
     *
     * In particular, w32tm /stripchart can issue Version 1 client-mode
     * requests. NTP/SNTP servers are expected to interoperate with previous
     * protocol versions and reply using the request version. Version 0
     * remains rejected.
     *
     * Use numeric bounds for Versions 1 and 2 because ntp_types.h currently
     * only needs named constants for Versions 3 and 4 elsewhere.
     */
    return request->version >= 1U &&
           request->version <= NTP_VERSION_4;
}

static void build_rate_kod(const ntp_packet_fields_t *request,
                           uint8_t response[NTP_PACKET_SIZE])
{
    ntp_packet_fields_t packet;

    memset(&packet, 0, sizeof(packet));

    packet.leap_indicator = NTP_LI_UNSYNCED;
    packet.version = request->version;
    packet.mode = NTP_MODE_SERVER;
    packet.stratum = NTP_STRATUM_KOD;
    packet.precision = -20;
    packet.reference_id = ntp_packet_refid_from_text("RATE");
    packet.origin_timestamp = request->transmit_timestamp;

    ntp_timestamp_t now;

    if (get_current_ntp_timestamp(&now)) {
        packet.reference_timestamp = now;
        packet.receive_timestamp = now;
        packet.transmit_timestamp = now;
    }

    ntp_packet_build(response, &packet);
}

static bool build_server_response(const ntp_packet_fields_t *request,
                                  ntp_timestamp_t receive_timestamp,
                                  uint8_t response[NTP_PACKET_SIZE],
                                  uint8_t *out_stratum,
                                  uint8_t *out_leap,
                                  uint32_t *out_dispersion,
                                  int64_t *out_tx_timestamp_complete_us,
                                  int64_t *out_packet_built_us)
{
    uint8_t stratum = NTP_STRATUM_UNSYNCED;
    uint8_t leap = NTP_LI_UNSYNCED;
    uint32_t refid = 0U;
    uint32_t dispersion = 0U;

    if (!get_server_quality(&stratum,
                            &leap,
                            &refid,
                            &dispersion)) {
        return false;
    }

    ntp_timestamp_t reference_timestamp;
    ntp_timestamp_t transmit_timestamp;

    if (!get_reference_ntp_timestamp(&reference_timestamp) ||
    !get_current_ntp_timestamp(&transmit_timestamp)) {
    return false;
}

    if (out_tx_timestamp_complete_us != NULL) {
        *out_tx_timestamp_complete_us = esp_timer_get_time();
    }

    ntp_packet_fields_t packet;

    memset(&packet, 0, sizeof(packet));

    packet.leap_indicator = leap;
    packet.version = request->version;
    packet.mode = NTP_MODE_SERVER;
    packet.stratum = stratum;
    packet.precision = -20;

    packet.root_delay = 0U;
    packet.root_dispersion = dispersion;
    packet.reference_id = refid;

    packet.reference_timestamp = reference_timestamp;
    packet.origin_timestamp = request->transmit_timestamp;
    packet.receive_timestamp = receive_timestamp;
    packet.transmit_timestamp = transmit_timestamp;

    ntp_packet_build(response, &packet);

    if (out_packet_built_us != NULL) {
        *out_packet_built_us = esp_timer_get_time();
    }

    if (out_stratum != NULL) {
        *out_stratum = stratum;
    }

    if (out_leap != NULL) {
        *out_leap = leap;
    }

    if (out_dispersion != NULL) {
        *out_dispersion = dispersion;
    }

    return true;
}

static int ntp_server_open_socket(void)
{
    const int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (socket_fd < 0) {
        return -1;
    }

    const int reuse = 1;

    (void)setsockopt(socket_fd,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &reuse,
                     sizeof(reuse));

    const struct timeval timeout = {
        .tv_sec = APP_NTP_RECEIVE_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };

    (void)setsockopt(socket_fd,
                     SOL_SOCKET,
                     SO_RCVTIMEO,
                     &timeout,
                     sizeof(timeout));

    const struct sockaddr_in server_address = {
        .sin_family = AF_INET,
        .sin_port = htons(NTP_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(socket_fd,
             (const struct sockaddr *)&server_address,
             sizeof(server_address)) < 0) {
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

static void ntp_server_task(void *arg)
{
    (void)arg;

    while (true) {
        const int socket_fd = ntp_server_open_socket();

        if (socket_fd < 0) {
            ntp_status_record_socket_failure();
            ntp_status_set_socket_bound(false);

            ESP_LOGW(TAG,
                     "UDP/123 bind failed; retrying in five seconds");

            vTaskDelay(pdMS_TO_TICKS(5000U));
            continue;
        }

        ntp_status_set_socket_bound(true);

        ESP_LOGI(TAG, "NTP UDP server listening on port %u", NTP_PORT);

        while (true) {
            struct sockaddr_in client_address;
            socklen_t client_length = sizeof(client_address);

            const int received = recvfrom(
                socket_fd,
                s_request_buffer,
                sizeof(s_request_buffer),
                0,
                (struct sockaddr *)&client_address,
                &client_length);

            if (received < 0) {
                continue;
            }

            const int64_t timing_recv_return_us = esp_timer_get_time();

            ntp_status_record_request(client_address.sin_addr.s_addr);

            eth_service_ntp_rx_timestamp_t hw_rx_timestamp = {0};
            const bool hw_rx_available = eth_service_take_ntp_rx_timestamp(
                client_address.sin_addr.s_addr,
                ntohs(client_address.sin_port),
                &hw_rx_timestamp);
            if (!hw_rx_available) {
                ntp_status_record_hw_rx_miss();
            }

            ntp_packet_fields_t request;

            if (!ntp_packet_parse(s_request_buffer,
                                  (size_t)received,
                                  &request) ||
                !valid_client_request(&request)) {
                ntp_status_record_invalid_request();
                continue;
            }

            const bool nts_request = nts_ntp_auth_request_present(
                s_request_buffer,
                (size_t)received);

            if (nts_request && request.version != NTP_VERSION_4) {
                ntp_status_record_invalid_request();
                continue;
            }

            bool send_kod = false;

            if (!ntp_rate_limit_allow(client_address.sin_addr.s_addr,
                                      &send_kod)) {
                if (send_kod && !nts_request) {
                    build_rate_kod(&request, s_response_buffer);

                    const int sent = sendto(
                        socket_fd,
                        s_response_buffer,
                        NTP_PACKET_SIZE,
                        0,
                        (const struct sockaddr *)&client_address,
                        client_length);

                    if (sent == (int)NTP_PACKET_SIZE) {
                        ntp_status_record_kod();
                    } else {
                        ntp_status_record_send_failure();
                    }
                }

                continue;
            }

            nts_ntp_auth_context_t nts_context;
            memset(&nts_context, 0, sizeof(nts_context));

            if (nts_request) {
                const esp_err_t nts_err = nts_ntp_auth_verify_request(
                    s_request_buffer,
                    (size_t)received,
                    &nts_context);

                if (nts_err != ESP_OK) {
                    ESP_LOGW(TAG,
                             "NTS request authentication failed: %s",
                             esp_err_to_name(nts_err));
                    nts_ntp_auth_clear_context(&nts_context);
                    ntp_status_record_invalid_request();
                    continue;
                }
            }

            ntp_timestamp_t software_receive_timestamp;
            const int64_t timing_rx_start_us = esp_timer_get_time();

            if (!get_current_ntp_timestamp(&software_receive_timestamp)) {
                nts_ntp_auth_clear_context(&nts_context);
                ntp_status_record_unsynchronized_drop();
                continue;
            }

            const int64_t timing_rx_complete_us = esp_timer_get_time();

            /* Phase 6C.4C: the EMAC descriptor timestamp is now the sole
             * authoritative NTP Receive Timestamp.  Once a request reaches
             * the normal-response path, never silently fall back to the
             * software timestamp: missing/mismatched/stale mapping fails
             * closed for that request. */
            if (!hw_rx_available) {
                nts_ntp_auth_clear_context(&nts_context);
                ntp_status_record_hw_rx_authority_drop();
                ESP_LOGW(TAG, "HW RX authority unavailable; dropping NTP request");
                continue;
            }

            ntp_status_record_hw_rx_comparison(software_receive_timestamp,
                                               &hw_rx_timestamp);

            const ntp_timestamp_t receive_timestamp = {
                .seconds = hw_rx_timestamp.seconds,
                .fraction = hw_rx_timestamp.fraction,
            };
            ntp_status_record_hw_rx_authoritative();

            uint8_t stratum = NTP_STRATUM_UNSYNCED;
            uint8_t leap = NTP_LI_UNSYNCED;
            uint32_t dispersion = 0U;
            int64_t timing_tx_complete_us = 0;
            int64_t timing_packet_built_us = 0;
            const int64_t timing_build_start_us = esp_timer_get_time();

            if (!build_server_response(&request,
                                       receive_timestamp,
                                       s_response_buffer,
                                       &stratum,
                                       &leap,
                                       &dispersion,
                                       &timing_tx_complete_us,
                                       &timing_packet_built_us)) {
                nts_ntp_auth_clear_context(&nts_context);
                ntp_status_record_unsynchronized_drop();
                continue;
            }

            size_t response_length = NTP_PACKET_SIZE;

            if (nts_request) {
                const esp_err_t nts_err = nts_ntp_auth_protect_response(
                    &nts_context,
                    s_response_buffer,
                    NTP_PACKET_SIZE,
                    sizeof(s_response_buffer),
                    &response_length);

                if (nts_err != ESP_OK) {
                    ESP_LOGW(TAG,
                             "NTS response protection failed: %s",
                             esp_err_to_name(nts_err));
                    nts_ntp_auth_clear_context(&nts_context);
                    ntp_status_record_send_failure();
                    continue;
                }

                timing_packet_built_us = esp_timer_get_time();
            }

            nts_ntp_auth_clear_context(&nts_context);

            const int64_t timing_send_start_us = esp_timer_get_time();

            const int sent = sendto(
                socket_fd,
                s_response_buffer,
                response_length,
                0,
                (const struct sockaddr *)&client_address,
                client_length);

            const int64_t timing_send_complete_us = esp_timer_get_time();

            if (sent == (int)response_length) {
                ntp_status_record_timing(
                    clamp_duration_us(timing_recv_return_us, timing_rx_start_us),
                    clamp_duration_us(timing_rx_start_us, timing_rx_complete_us),
                    clamp_duration_us(timing_build_start_us, timing_packet_built_us),
                    clamp_duration_us(timing_tx_complete_us, timing_send_start_us),
                    clamp_duration_us(timing_send_start_us, timing_send_complete_us),
                    clamp_duration_us(timing_recv_return_us, timing_send_complete_us));

                ntp_status_record_response(stratum,
                                           leap,
                                           dispersion);
            } else {
                ntp_status_record_send_failure();
            }
        }
    }
}

esp_err_t ntp_server_start(void)
{
    if (s_started) {
        return ESP_OK;
    }

    ntp_rate_limit_init();

    portENTER_CRITICAL(&s_ntp_lock);

    memset(&s_status, 0, sizeof(s_status));
    memset(&s_timing_sums, 0, sizeof(s_timing_sums));
    s_hw_rx_delta_sum_ns = 0;
    s_status.started = true;
    s_status.advertised_stratum = NTP_STRATUM_UNSYNCED;
    s_status.advertised_leap_indicator = NTP_LI_UNSYNCED;

    portEXIT_CRITICAL(&s_ntp_lock);

    const BaseType_t task_created = xTaskCreate(
        ntp_server_task,
        "ntp_server",
        APP_NTP_TASK_STACK_SIZE,
        NULL,
        APP_NTP_TASK_PRIORITY,
        NULL);

    if (task_created != pdPASS) {
        portENTER_CRITICAL(&s_ntp_lock);
        memset(&s_status, 0, sizeof(s_status));
        portEXIT_CRITICAL(&s_ntp_lock);

        return ESP_ERR_NO_MEM;
    }

    s_started = true;

    return ESP_OK;
}

bool ntp_server_get_status(ntp_server_status_t *out_status)
{
    if (out_status == NULL) {
        return false;
    }

    portENTER_CRITICAL(&s_ntp_lock);
    *out_status = s_status;
    portEXIT_CRITICAL(&s_ntp_lock);

    return true;
}