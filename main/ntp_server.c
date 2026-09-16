#include "ntp_server.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "app_state.h"
#include "clock_discipline.h"
#include "gnss_service.h"
#include "ntp_packet.h"
#include "ntp_rate_limit.h"
#include "ntp_types.h"

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

static bool valid_client_request(const ntp_packet_fields_t *request)
{
    if (request == NULL) {
        return false;
    }

    if (request->mode != NTP_MODE_CLIENT) {
        return false;
    }

    return request->version == NTP_VERSION_3 ||
           request->version == NTP_VERSION_4;
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
                                  uint32_t *out_dispersion)
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

    ntp_timestamp_t transmit_timestamp;

    if (!get_current_ntp_timestamp(&transmit_timestamp)) {
        return false;
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

    packet.reference_timestamp = transmit_timestamp;
    packet.origin_timestamp = request->transmit_timestamp;
    packet.receive_timestamp = receive_timestamp;
    packet.transmit_timestamp = transmit_timestamp;

    ntp_packet_build(response, &packet);

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

    uint8_t request_buffer[256];
    uint8_t response_buffer[NTP_PACKET_SIZE];

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
                request_buffer,
                sizeof(request_buffer),
                0,
                (struct sockaddr *)&client_address,
                &client_length);

            if (received < 0) {
                continue;
            }

            ntp_status_record_request(client_address.sin_addr.s_addr);

            ntp_packet_fields_t request;

            if (!ntp_packet_parse(request_buffer,
                                  (size_t)received,
                                  &request) ||
                !valid_client_request(&request)) {
                ntp_status_record_invalid_request();
                continue;
            }

            bool send_kod = false;

            if (!ntp_rate_limit_allow(client_address.sin_addr.s_addr,
                                      &send_kod)) {
                if (send_kod) {
                    build_rate_kod(&request, response_buffer);

                    const int sent = sendto(
                        socket_fd,
                        response_buffer,
                        sizeof(response_buffer),
                        0,
                        (const struct sockaddr *)&client_address,
                        client_length);

                    if (sent == (int)sizeof(response_buffer)) {
                        ntp_status_record_kod();
                    } else {
                        ntp_status_record_send_failure();
                    }
                }

                continue;
            }

            ntp_timestamp_t receive_timestamp;

            if (!get_current_ntp_timestamp(&receive_timestamp)) {
                ntp_status_record_unsynchronized_drop();
                continue;
            }

            uint8_t stratum = NTP_STRATUM_UNSYNCED;
            uint8_t leap = NTP_LI_UNSYNCED;
            uint32_t dispersion = 0U;

            if (!build_server_response(&request,
                                       receive_timestamp,
                                       response_buffer,
                                       &stratum,
                                       &leap,
                                       &dispersion)) {
                ntp_status_record_unsynchronized_drop();
                continue;
            }

            const int sent = sendto(
                socket_fd,
                response_buffer,
                sizeof(response_buffer),
                0,
                (const struct sockaddr *)&client_address,
                client_length);

            if (sent == (int)sizeof(response_buffer)) {
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