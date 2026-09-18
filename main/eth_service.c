#include "eth_service.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "app_config.h"
#include "app_state.h"
#include "clock_discipline.h"

#include "esp_check.h"
#include "esp_eth.h"
#include "esp_eth_mac_esp.h"
#include "esp_eth_phy_ip101.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/portmacro.h"
#include "freertos/task.h"

static const char *TAG = "ETH";

#define ETH_IP_READY_BIT                         BIT0
#define ETH_PTP_CORRELATION_PERIOD_MS             10000U
#define ETH_PTP_CORRELATION_INITIAL_DELAY_MS       5000U
#define ETHERTYPE_IPV4                              0x0800U
#define ETHERTYPE_VLAN                              0x8100U
#define ETHERTYPE_QINQ                              0x88A8U
#define IP_PROTOCOL_UDP                             17U
#define NTP_UDP_PORT                                123U
#define ETH_NTP_RX_QUEUE_SIZE                        16U
#define ETH_PTP_CORRELATION_MAX_AGE_US          30000000LL
#define ETH_PTP_LOCAL_MAP_MAX_BRACKET_NS          250000ULL
#define ETH_NTP_TX_COMPENSATION_NS                    98941ULL

static esp_eth_handle_t s_eth_handle;
static esp_eth_mac_t *s_eth_mac;
static esp_netif_t *s_eth_netif;
static EventGroupHandle_t s_eth_events;

static portMUX_TYPE s_eth_lock = portMUX_INITIALIZER_UNLOCKED;
static eth_service_status_t s_status;

typedef struct {
    bool valid;
    uint32_t client_ipv4;
    uint16_t client_port;
    uint32_t sequence;
    eth_mac_time_t ptp_time;
} eth_ntp_rx_queue_entry_t;

static eth_ntp_rx_queue_entry_t s_ntp_rx_queue[ETH_NTP_RX_QUEUE_SIZE];
static uint32_t s_ntp_rx_queue_next;
static uint32_t s_ntp_rx_queue_sequence;

#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
typedef struct {
    uint32_t matched;
    uint32_t tx_success;
    uint32_t tx_fail;
    uint32_t timestamp_valid;
    uint32_t timestamp_invalid;
    uint32_t last_seconds;
    uint32_t last_nanoseconds;
} eth_ntp_tx_probe_status_t;

static eth_ntp_tx_probe_status_t s_ntp_tx_probe;

static TaskHandle_t s_ptp_correlation_task;
static bool s_ptp_correlation_baseline_valid;
static int64_t s_ptp_correlation_baseline_offset_ns;
static uint64_t s_ptp_correlation_baseline_utc_ns;
static int64_t s_ptp_correlation_last_monotonic_us;
#endif

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static bool eth_frame_is_ipv4_udp_ntp_response(const uint8_t *buffer, size_t length);

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

typedef struct {
    size_t udp_offset;
    size_t ntp_offset;
    uint16_t udp_checksum;
    uint16_t old_xmt_words[4];
} eth_ntp_tx_late_stamp_ctx_t;

/* Phase 6C.7: do all frame qualification before taking T3. The post-T3
 * critical path then changes only the four 16-bit XMT words and updates the
 * existing UDP checksum incrementally. */
static bool eth_frame_prepare_ntp_late_stamp(const uint8_t *buffer,
                                              size_t length,
                                              eth_ntp_tx_late_stamp_ctx_t *ctx)
{
    if (buffer == NULL || ctx == NULL ||
        !eth_frame_is_ipv4_udp_ntp_response(buffer, length)) {
        return false;
    }

    size_t l3_offset = 14U;
    uint16_t ether_type = read_be16(buffer + 12U);
    for (unsigned tag = 0; tag < 2U &&
         (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ); tag++) {
        if (length < l3_offset + 4U) {
            return false;
        }
        ether_type = read_be16(buffer + l3_offset + 2U);
        l3_offset += 4U;
    }

    if (ether_type != ETHERTYPE_IPV4 || length < l3_offset + 20U) {
        return false;
    }

    const size_t ip_header_len = (size_t)(buffer[l3_offset] & 0x0FU) * 4U;
    if (ip_header_len < 20U || length < l3_offset + ip_header_len + 8U) {
        return false;
    }

    /* Require a complete, unfragmented IPv4 datagram for mutation. */
    const uint16_t fragment = read_be16(buffer + l3_offset + 6U);
    if ((fragment & 0x3FFFU) != 0U) {
        return false;
    }

    const uint16_t ip_total_length = read_be16(buffer + l3_offset + 2U);
    const size_t udp_offset = l3_offset + ip_header_len;
    const uint16_t udp_length = read_be16(buffer + udp_offset + 4U);

    if (udp_length != 56U ||
        ip_total_length != ip_header_len + (size_t)udp_length ||
        length < udp_offset + (size_t)udp_length) {
        return false;
    }

    const size_t ntp_offset = udp_offset + 8U;
    const uint8_t *ntp = buffer + ntp_offset;
    const uint8_t mode = ntp[0] & 0x07U;
    const uint8_t stratum = ntp[1];
    if (mode != 4U || stratum == 0U) {
        return false;
    }

    /* An IPv4 UDP checksum of zero means checksum disabled. This firmware's
     * normal NTP path supplies a checksum; fail closed rather than introduce
     * a special slow path after the T3 sample. */
    const uint16_t udp_checksum = read_be16(buffer + udp_offset + 6U);
    if (udp_checksum == 0U) {
        return false;
    }

    ctx->udp_offset = udp_offset;
    ctx->ntp_offset = ntp_offset;
    ctx->udp_checksum = udp_checksum;
    for (unsigned i = 0; i < 4U; i++) {
        ctx->old_xmt_words[i] = read_be16(ntp + 40U + (2U * i));
    }
    return true;
}

static uint16_t checksum_replace_word(uint16_t checksum,
                                      uint16_t old_word,
                                      uint16_t new_word)
{
    uint32_t sum = (uint32_t)(~checksum & 0xFFFFU) +
                   (uint32_t)(~old_word & 0xFFFFU) +
                   (uint32_t)new_word;
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static bool eth_frame_apply_ntp_late_stamp(uint8_t *buffer,
                                            const eth_ntp_tx_late_stamp_ctx_t *ctx,
                                            const clock_ntp_timestamp_t *timestamp)
{
    if (buffer == NULL || ctx == NULL || timestamp == NULL) {
        return false;
    }

    uint8_t *ntp = buffer + ctx->ntp_offset;
    uint16_t new_words[4] = {
        (uint16_t)(timestamp->seconds >> 16),
        (uint16_t)timestamp->seconds,
        (uint16_t)(timestamp->fraction >> 16),
        (uint16_t)timestamp->fraction,
    };

    uint16_t checksum = ctx->udp_checksum;
    for (unsigned i = 0; i < 4U; i++) {
        checksum = checksum_replace_word(checksum,
                                         ctx->old_xmt_words[i],
                                         new_words[i]);
    }
    if (checksum == 0U) {
        checksum = 0xFFFFU;
    }

    write_be32(ntp + 40U, timestamp->seconds);
    write_be32(ntp + 44U, timestamp->fraction);
    write_be16(buffer + ctx->udp_offset + 6U, checksum);
    return true;
}

static bool eth_frame_is_ipv4_udp_ntp(const uint8_t *buffer, uint32_t length)
{
    if (buffer == NULL || length < 14U) {
        return false;
    }

    uint32_t l3_offset = 14U;
    uint16_t ether_type = read_be16(buffer + 12U);

    /* Accept up to two VLAN tags without altering the frame. */
    for (unsigned tag = 0; tag < 2U &&
         (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ); tag++) {
        if (length < l3_offset + 4U) {
            return false;
        }
        ether_type = read_be16(buffer + l3_offset + 2U);
        l3_offset += 4U;
    }

    if (ether_type != ETHERTYPE_IPV4 || length < l3_offset + 20U) {
        return false;
    }

    const uint8_t version_ihl = buffer[l3_offset];
    if ((version_ihl >> 4) != 4U) {
        return false;
    }

    const uint32_t ip_header_len = (uint32_t)(version_ihl & 0x0FU) * 4U;
    if (ip_header_len < 20U || length < l3_offset + ip_header_len + 8U) {
        return false;
    }

    if (buffer[l3_offset + 9U] != IP_PROTOCOL_UDP) {
        return false;
    }

    /* Non-first IPv4 fragments do not contain the UDP header. */
    const uint16_t fragment = read_be16(buffer + l3_offset + 6U);
    if ((fragment & 0x1FFFU) != 0U) {
        return false;
    }

    const uint32_t udp_offset = l3_offset + ip_header_len;
    const uint16_t destination_port = read_be16(buffer + udp_offset + 2U);
    return destination_port == NTP_UDP_PORT;
}

static bool eth_frame_is_ipv4_udp_ntp_response(const uint8_t *buffer, size_t length)
{
    if (buffer == NULL || length < 14U) {
        return false;
    }

    size_t l3_offset = 14U;
    uint16_t ether_type = read_be16(buffer + 12U);

    /* Match the RX parser's VLAN handling: accept up to two tags. */
    for (unsigned tag = 0; tag < 2U &&
         (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ); tag++) {
        if (length < l3_offset + 4U) {
            return false;
        }
        ether_type = read_be16(buffer + l3_offset + 2U);
        l3_offset += 4U;
    }

    if (ether_type != ETHERTYPE_IPV4 || length < l3_offset + 20U) {
        return false;
    }

    const uint8_t version_ihl = buffer[l3_offset];
    if ((version_ihl >> 4) != 4U) {
        return false;
    }

    const size_t ip_header_len = (size_t)(version_ihl & 0x0FU) * 4U;
    if (ip_header_len < 20U || length < l3_offset + ip_header_len + 8U) {
        return false;
    }

    if (buffer[l3_offset + 9U] != IP_PROTOCOL_UDP) {
        return false;
    }

    /* Non-first IPv4 fragments do not contain the UDP header. */
    const uint16_t fragment = read_be16(buffer + l3_offset + 6U);
    if ((fragment & 0x1FFFU) != 0U) {
        return false;
    }

    const size_t udp_offset = l3_offset + ip_header_len;
    const uint16_t source_port = read_be16(buffer + udp_offset);
    return source_port == NTP_UDP_PORT;
}

#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
static uint64_t ntp_timestamp_to_ns(const clock_ntp_timestamp_t *timestamp);
static uint64_t ptp_timestamp_to_ns(const eth_mac_time_t *timestamp);
#endif

static bool eth_frame_get_ntp_response_xmt(const uint8_t *buffer,
                                           size_t length,
                                           uint32_t *out_seconds,
                                           uint32_t *out_fraction)
{
    if (buffer == NULL || out_seconds == NULL || out_fraction == NULL ||
        !eth_frame_is_ipv4_udp_ntp_response(buffer, length)) {
        return false;
    }

    size_t l3_offset = 14U;
    uint16_t ether_type = read_be16(buffer + 12U);

    for (unsigned tag = 0; tag < 2U &&
         (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ); tag++) {
        ether_type = read_be16(buffer + l3_offset + 2U);
        l3_offset += 4U;
    }

    const size_t ip_header_len = (size_t)(buffer[l3_offset] & 0x0FU) * 4U;
    const size_t ntp_offset = l3_offset + ip_header_len + 8U;

    /* NTP Transmit Timestamp is bytes 40..47 of the 48-byte NTP packet. */
    if (length < ntp_offset + 48U) {
        return false;
    }

    *out_seconds = read_be32(buffer + ntp_offset + 40U);
    *out_fraction = read_be32(buffer + ntp_offset + 44U);
    return true;
}

#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
static bool eth_map_ptp_event_to_utc_ns(const eth_mac_time_t *event_ptp,
                                        uint64_t *out_utc_ns,
                                        uint32_t *out_bracket_ns,
                                        uint32_t *out_age_us)
{
    if (event_ptp == NULL || out_utc_ns == NULL || s_eth_mac == NULL) {
        return false;
    }

    clock_ntp_timestamp_t utc_before = {0};
    clock_ntp_timestamp_t utc_after = {0};
    eth_mac_time_t ptp_now = {0};

    if (!clock_discipline_get_ntp_timestamp(&utc_before) ||
        esp_eth_mac_get_ptp_time(s_eth_mac, &ptp_now) != ESP_OK ||
        !clock_discipline_get_ntp_timestamp(&utc_after)) {
        return false;
    }

    const uint64_t utc_before_ns = ntp_timestamp_to_ns(&utc_before);
    const uint64_t utc_after_ns = ntp_timestamp_to_ns(&utc_after);
    const uint64_t ptp_now_ns = ptp_timestamp_to_ns(&ptp_now);
    const uint64_t event_ptp_ns = ptp_timestamp_to_ns(event_ptp);

    if (utc_after_ns < utc_before_ns || ptp_now_ns < event_ptp_ns) {
        return false;
    }

    const uint64_t bracket_ns = utc_after_ns - utc_before_ns;
    const uint64_t utc_mid_ns = utc_before_ns + bracket_ns / 2ULL;
    const uint64_t ptp_age_ns = ptp_now_ns - event_ptp_ns;

    int64_t rate_ppb = 0;
    int64_t correlation_last_us = 0;
    uint32_t correlation_samples = 0U;
    bool correlation_valid = false;

    portENTER_CRITICAL(&s_eth_lock);
    correlation_valid = s_status.ptp_correlation_valid;
    correlation_samples = s_status.ptp_correlation_samples;
    rate_ppb = s_status.ptp_utc_estimated_rate_ppb;
    correlation_last_us = s_ptp_correlation_last_monotonic_us;
    portEXIT_CRITICAL(&s_eth_lock);

    const int64_t now_us = esp_timer_get_time();
    if (!correlation_valid || correlation_samples < 2U ||
        correlation_last_us <= 0 || now_us < correlation_last_us ||
        (now_us - correlation_last_us) > ETH_PTP_CORRELATION_MAX_AGE_US ||
        bracket_ns > ETH_PTP_LOCAL_MAP_MAX_BRACKET_NS) {
        return false;
    }

    const int64_t denominator = 1000000000LL + rate_ppb;
    if (denominator <= 0) {
        return false;
    }

    const uint64_t denominator_u = (uint64_t)denominator;
    const uint64_t age_quotient = ptp_age_ns / denominator_u;
    const uint64_t age_remainder = ptp_age_ns % denominator_u;
    const uint64_t utc_age_ns =
        age_quotient * 1000000000ULL +
        (age_remainder * 1000000000ULL + denominator_u / 2ULL) / denominator_u;

    if (utc_age_ns > utc_mid_ns) {
        return false;
    }

    *out_utc_ns = utc_mid_ns - utc_age_ns;
    if (out_bracket_ns != NULL) {
        *out_bracket_ns = bracket_ns > UINT32_MAX ? UINT32_MAX : (uint32_t)bracket_ns;
    }
    if (out_age_us != NULL) {
        const uint64_t age_us = ptp_age_ns / 1000ULL;
        *out_age_us = age_us > UINT32_MAX ? UINT32_MAX : (uint32_t)age_us;
    }
    return true;
}
#endif

static void eth_tx_probe_l2_free(void *h, void *buffer)
{
    (void)h;
    free(buffer);
}

static esp_err_t eth_tx_probe_set_mac_filter(void *h,
                                              const uint8_t *eth_mac,
                                              size_t mac_len,
                                              bool add)
{
    esp_eth_handle_t eth_handle = (esp_eth_handle_t)h;

    if (eth_mac == NULL || mac_len != 6U) {
        return ESP_ERR_INVALID_ARG;
    }

    if (add) {
        return esp_eth_ioctl(eth_handle,
                             ETH_CMD_ADD_MAC_FILTER,
                             (void *)eth_mac);
    }

    return esp_eth_ioctl(eth_handle,
                         ETH_CMD_DEL_MAC_FILTER,
                         (void *)eth_mac);
}

static esp_err_t eth_ntp_tx_probe_transmit(void *h, void *buffer, size_t length)
{
    esp_eth_handle_t eth_handle = (esp_eth_handle_t)h;

    /* Fail open to the stock path unless this is positively identified as an
     * IPv4 UDP NTP server response. */
    if (!eth_frame_is_ipv4_udp_ntp_response((const uint8_t *)buffer, length)) {
        return esp_eth_transmit(eth_handle, buffer, length);
    }

#ifndef SOC_EMAC_IEEE1588V2_SUPPORTED
    return esp_eth_transmit(eth_handle, buffer, length);
#else
    /* Phase 6C.7: qualify and cache all invariant packet state before the
     * final disciplined-UTC sample. After T3 is taken, only four XMT words
     * plus an incremental UDP-checksum update remain before MAC handoff.
     * No empirical TX-delay compensation is applied in this build. */
    eth_ntp_tx_late_stamp_ctx_t late_stamp_ctx = {0};
    const bool late_stamp_ready =
        eth_frame_prepare_ntp_late_stamp((const uint8_t *)buffer,
                                         length,
                                         &late_stamp_ctx);

    clock_ntp_timestamp_t late_sw_timestamp = {0};
    const bool late_sw_valid =
        late_stamp_ready &&
        clock_discipline_get_ntp_timestamp(&late_sw_timestamp);

    /* Phase 6C.7B: predict the descriptor-authoritative TX instant from the
     * frozen 6C.7A steady-state median residual. Keep late_sw_timestamp raw
     * so the existing late-hw diagnostic continues to report uncompensated
     * L2-to-HW latency independently of the predicted XMT. */
    clock_ntp_timestamp_t predicted_tx_timestamp = late_sw_timestamp;
    if (late_sw_valid) {
        const uint64_t fraction_delta =
            ((ETH_NTP_TX_COMPENSATION_NS << 32) + 500000000ULL) /
            1000000000ULL;
        const uint64_t fraction_sum =
            (uint64_t)predicted_tx_timestamp.fraction + fraction_delta;
        predicted_tx_timestamp.seconds += (uint32_t)(fraction_sum >> 32);
        predicted_tx_timestamp.fraction = (uint32_t)fraction_sum;
    }

    const bool late_stamp_applied =
        late_sw_valid &&
        eth_frame_apply_ntp_late_stamp((uint8_t *)buffer,
                                       &late_stamp_ctx,
                                       &predicted_tx_timestamp);

    uint32_t xmt_seconds = 0U;
    uint32_t xmt_fraction = 0U;
    const bool xmt_valid =
        eth_frame_get_ntp_response_xmt((const uint8_t *)buffer,
                                       length,
                                       &xmt_seconds,
                                       &xmt_fraction);

    eth_mac_time_t tx_timestamp = {0};

    const esp_err_t tx_err =
        esp_eth_transmit_ctrl_vargs(eth_handle,
                                    &tx_timestamp,
                                    2U,
                                    (uint8_t *)buffer,
                                    (uint32_t)length);

    const bool timestamp_valid =
        tx_timestamp.seconds != 0U || tx_timestamp.nanoseconds != 0U;

    uint32_t sample = 0U;

    portENTER_CRITICAL(&s_eth_lock);
    s_ntp_tx_probe.matched++;
    sample = s_ntp_tx_probe.matched;

    if (tx_err == ESP_OK) {
        s_ntp_tx_probe.tx_success++;
        if (timestamp_valid) {
            s_ntp_tx_probe.timestamp_valid++;
            s_ntp_tx_probe.last_seconds = tx_timestamp.seconds;
            s_ntp_tx_probe.last_nanoseconds = tx_timestamp.nanoseconds;
        } else {
            s_ntp_tx_probe.timestamp_invalid++;
        }
    } else {
        s_ntp_tx_probe.tx_fail++;
    }
    portEXIT_CRITICAL(&s_eth_lock);

    if (tx_err != ESP_OK) {
        ESP_LOGW(TAG,
                 "HW TX NTP transmit failed: n=%" PRIu32 " err=%s",
                 sample,
                 esp_err_to_name(tx_err));
    } else if (timestamp_valid) {
        ESP_LOGI(TAG,
                 "HW TX NTP timestamp: n=%" PRIu32
                 " ptp=%" PRIu32 ".%09" PRIu32,
                 sample,
                 tx_timestamp.seconds,
                 tx_timestamp.nanoseconds);

        uint64_t hw_tx_utc_ns = 0ULL;
        uint32_t mapping_bracket_ns = 0U;
        uint32_t mapping_age_us = 0U;

        if (xmt_valid &&
            eth_map_ptp_event_to_utc_ns(&tx_timestamp,
                                        &hw_tx_utc_ns,
                                        &mapping_bracket_ns,
                                        &mapping_age_us)) {
            const uint64_t xmt_fractional_ns =
                (((uint64_t)xmt_fraction * 1000000000ULL) + 0x80000000ULL) >> 32;
            const uint64_t software_xmt_ns =
                ((uint64_t)xmt_seconds * 1000000000ULL) + xmt_fractional_ns;
            const int64_t delta_ns =
                (int64_t)software_xmt_ns - (int64_t)hw_tx_utc_ns;

            ESP_LOGI(TAG,
                     "HW TX NTP compare: n=%" PRIu32
                     " xmt-hw=%" PRId64
                     " ns map_bracket=%" PRIu32 " ns age=%" PRIu32 " us",
                     sample,
                     delta_ns,
                     mapping_bracket_ns,
                     mapping_age_us);

            if (late_sw_valid) {
                const uint64_t late_sw_ns =
                    ntp_timestamp_to_ns(&late_sw_timestamp);
                const int64_t late_delta_ns =
                    (int64_t)late_sw_ns - (int64_t)hw_tx_utc_ns;

                ESP_LOGI(TAG,
                         "HW TX late compare: n=%" PRIu32
                         " late-hw=%" PRId64 " ns stamped=%u",
                         sample,
                         late_delta_ns,
                         late_stamp_applied ? 1U : 0U);
            } else {
                ESP_LOGW(TAG,
                         "HW TX late compare unavailable: n=%" PRIu32
                         " disciplined UTC unavailable",
                         sample);
            }
        } else if (!xmt_valid) {
            ESP_LOGW(TAG,
                     "HW TX NTP compare unavailable: n=%" PRIu32
                     " serialized XMT unavailable",
                     sample);
        } else {
            ESP_LOGW(TAG,
                     "HW TX NTP compare unavailable: n=%" PRIu32
                     " PTP/UTC mapping unavailable",
                     sample);
        }
    } else {
        ESP_LOGW(TAG,
                 "HW TX NTP timestamp invalid: n=%" PRIu32,
                 sample);
    }

    return tx_err;
#endif
}

static bool eth_frame_get_ntp_client(const uint8_t *buffer, uint32_t length,
                                     uint32_t *out_ipv4, uint16_t *out_port)
{
    if (!eth_frame_is_ipv4_udp_ntp(buffer, length) || out_ipv4 == NULL || out_port == NULL) {
        return false;
    }

    uint32_t l3_offset = 14U;
    uint16_t ether_type = read_be16(buffer + 12U);
    for (unsigned tag = 0; tag < 2U &&
         (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ); tag++) {
        ether_type = read_be16(buffer + l3_offset + 2U);
        l3_offset += 4U;
    }

    const uint32_t ip_header_len = (uint32_t)(buffer[l3_offset] & 0x0FU) * 4U;
    const uint32_t udp_offset = l3_offset + ip_header_len;

    /* memcpy preserves the representation used by sockaddr_in.sin_addr.s_addr. */
    memcpy(out_ipv4, buffer + l3_offset + 12U, sizeof(*out_ipv4));
    *out_port = read_be16(buffer + udp_offset);
    return true;
}

static esp_err_t eth_input_to_netif_with_timestamp(esp_eth_handle_t eth_handle,
                                                    uint8_t *buffer,
                                                    uint32_t length,
                                                    void *priv,
                                                    void *info)
{
    (void)eth_handle;

#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
    const eth_mac_time_t *timestamp = (const eth_mac_time_t *)info;
    const bool timestamp_valid =
        timestamp != NULL &&
        (timestamp->seconds != 0U || timestamp->nanoseconds != 0U);
    const bool is_ntp = eth_frame_is_ipv4_udp_ntp(buffer, length);
    uint32_t client_ipv4 = 0U;
    uint16_t client_port = 0U;
    const bool client_valid = is_ntp &&
        eth_frame_get_ntp_client(buffer, length, &client_ipv4, &client_port);

    uint32_t ntp_sample = 0U;

    portENTER_CRITICAL(&s_eth_lock);
    s_status.rx_hw_frames++;
    if (timestamp_valid) {
        s_status.rx_hw_timestamp_valid++;
    } else {
        s_status.rx_hw_timestamp_invalid++;
    }

    if (is_ntp) {
        s_status.rx_hw_ntp_requests++;
        ntp_sample = s_status.rx_hw_ntp_requests;
        if (timestamp_valid) {
            s_status.rx_hw_ntp_timestamp_valid++;
            s_status.rx_hw_last_ntp_seconds = timestamp->seconds;
            s_status.rx_hw_last_ntp_nanoseconds = timestamp->nanoseconds;

            if (client_valid) {
                eth_ntp_rx_queue_entry_t *entry = &s_ntp_rx_queue[s_ntp_rx_queue_next];
                if (entry->valid) {
                    s_status.rx_hw_queue_overruns++;
                }
                entry->valid = true;
                entry->client_ipv4 = client_ipv4;
                entry->client_port = client_port;
                entry->sequence = ++s_ntp_rx_queue_sequence;
                entry->ptp_time = *timestamp;
                s_ntp_rx_queue_next = (s_ntp_rx_queue_next + 1U) % ETH_NTP_RX_QUEUE_SIZE;
                s_status.rx_hw_queue_enqueued++;
            }
        } else {
            s_status.rx_hw_ntp_timestamp_invalid++;
        }
    }
    portEXIT_CRITICAL(&s_eth_lock);

    if (is_ntp) {
        if (timestamp_valid) {
            ESP_LOGI(TAG,
                     "HW RX NTP timestamp: n=%" PRIu32 " ptp=%" PRIu32 ".%09" PRIu32,
                     ntp_sample,
                     timestamp->seconds,
                     timestamp->nanoseconds);
        } else {
            ESP_LOGW(TAG,
                     "HW RX NTP timestamp invalid: n=%" PRIu32,
                     ntp_sample);
        }
    }
#else
    (void)info;
#endif

    /* Preserve the stock Ethernet glue behavior: it forwards the received
     * Ethernet buffer to esp-netif and does not pass MAC-specific info on. */
    return esp_netif_receive((esp_netif_t *)priv, buffer, length, NULL);
}

#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
static uint64_t ntp_timestamp_to_ns(const clock_ntp_timestamp_t *timestamp)
{
    const uint64_t fractional_ns =
        (((uint64_t)timestamp->fraction * 1000000000ULL) + 0x80000000ULL) >> 32;

    return ((uint64_t)timestamp->seconds * 1000000000ULL) + fractional_ns;
}

static uint64_t ptp_timestamp_to_ns(const eth_mac_time_t *timestamp)
{
    return ((uint64_t)timestamp->seconds * 1000000000ULL) +
           (uint64_t)timestamp->nanoseconds;
}

static void eth_ptp_correlation_sample(void)
{
    if (s_eth_mac == NULL) {
        return;
    }

    clock_ntp_timestamp_t utc_before = {0};
    clock_ntp_timestamp_t utc_after = {0};
    eth_mac_time_t ptp_time = {0};

    if (!clock_discipline_get_ntp_timestamp(&utc_before)) {
        return;
    }

    const esp_err_t ptp_err = esp_eth_mac_get_ptp_time(s_eth_mac, &ptp_time);

    if (ptp_err != ESP_OK) {
        ESP_LOGW(TAG, "PTP correlation read failed: %s", esp_err_to_name(ptp_err));
        return;
    }

    if (!clock_discipline_get_ntp_timestamp(&utc_after)) {
        return;
    }

    const uint64_t utc_before_ns = ntp_timestamp_to_ns(&utc_before);
    const uint64_t utc_after_ns = ntp_timestamp_to_ns(&utc_after);

    if (utc_after_ns < utc_before_ns) {
        ESP_LOGW(TAG, "PTP correlation skipped: disciplined clock moved backwards");
        return;
    }

    const uint64_t bracket_ns = utc_after_ns - utc_before_ns;
    const uint64_t utc_mid_ns = utc_before_ns + (bracket_ns / 2ULL);
    const uint64_t ptp_ns = ptp_timestamp_to_ns(&ptp_time);
    const int64_t offset_ns = (int64_t)ptp_ns - (int64_t)utc_mid_ns;

    int64_t offset_change_ns = 0;
    int64_t estimated_rate_ppb = 0;

    if (!s_ptp_correlation_baseline_valid) {
        s_ptp_correlation_baseline_valid = true;
        s_ptp_correlation_baseline_offset_ns = offset_ns;
        s_ptp_correlation_baseline_utc_ns = utc_mid_ns;
    } else {
        offset_change_ns = offset_ns - s_ptp_correlation_baseline_offset_ns;
        const uint64_t elapsed_ns = utc_mid_ns - s_ptp_correlation_baseline_utc_ns;

        if (elapsed_ns > 0ULL) {
            estimated_rate_ppb =
                (offset_change_ns * 1000000000LL) / (int64_t)elapsed_ns;
        }
    }

    uint32_t sample_number = 0U;

    portENTER_CRITICAL(&s_eth_lock);
    s_status.ptp_correlation_valid = true;
    s_status.ptp_correlation_samples++;
    sample_number = s_status.ptp_correlation_samples;
    s_status.ptp_utc_offset_ns = offset_ns;
    s_status.ptp_utc_offset_change_ns = offset_change_ns;
    s_status.ptp_utc_estimated_rate_ppb = estimated_rate_ppb;
    s_status.ptp_utc_bracket_ns =
        (bracket_ns > UINT32_MAX) ? UINT32_MAX : (uint32_t)bracket_ns;
    s_ptp_correlation_last_monotonic_us = esp_timer_get_time();
    portEXIT_CRITICAL(&s_eth_lock);

    ESP_LOGI(TAG,
             "PTP correlation: n=%" PRIu32
             " offset=%" PRId64 " ns delta=%" PRId64
             " ns rate=%" PRId64 " ppb bracket=%" PRIu64 " ns",
             sample_number,
             offset_ns,
             offset_change_ns,
             estimated_rate_ppb,
             bracket_ns);
}

static void eth_ptp_correlation_task(void *arg)
{
    (void)arg;

    vTaskDelay(pdMS_TO_TICKS(ETH_PTP_CORRELATION_INITIAL_DELAY_MS));

    while (true) {
        eth_ptp_correlation_sample();
        vTaskDelay(pdMS_TO_TICKS(ETH_PTP_CORRELATION_PERIOD_MS));
    }
}
#endif

static void eth_ptp_probe(void)
{
#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
    if (s_eth_mac == NULL) {
        ESP_LOGW(TAG, "PTP probe skipped: EMAC instance unavailable");
        return;
    }

    const eth_mac_ptp_config_t ptp_config = ETH_MAC_ESP_PTP_DEFAULT_CONFIG();
    const esp_err_t enable_err = esp_eth_mac_ptp_enable(s_eth_mac, &ptp_config);

    if (enable_err != ESP_OK) {
        ESP_LOGW(TAG,
                 "EMAC PTP enable failed: %s",
                 esp_err_to_name(enable_err));
        return;
    }

    const esp_err_t ts4all_err = esp_eth_mac_enable_ts4all(s_eth_mac, true);
    const bool ts4all_enabled = (ts4all_err == ESP_OK);

    if (!ts4all_enabled) {
        ESP_LOGW(TAG,
                 "EMAC timestamp-all enable failed: %s",
                 esp_err_to_name(ts4all_err));
    }

    const uint32_t resolution_ns = esp_eth_mac_get_ts_resolution(s_eth_mac);

    eth_mac_time_t first_time = {0};
    eth_mac_time_t second_time = {0};

    const esp_err_t first_err =
        esp_eth_mac_get_ptp_time(s_eth_mac, &first_time);

    if (first_err == ESP_OK) {
        vTaskDelay(pdMS_TO_TICKS(10U));
    }

    const esp_err_t second_err =
        (first_err == ESP_OK)
            ? esp_eth_mac_get_ptp_time(s_eth_mac, &second_time)
            : first_err;

    const bool clock_readable =
        (first_err == ESP_OK) && (second_err == ESP_OK);
    const bool clock_running =
        clock_readable &&
        (memcmp(&first_time, &second_time, sizeof(first_time)) != 0);

    portENTER_CRITICAL(&s_eth_lock);
    s_status.ptp_supported = true;
    s_status.ptp_enabled = true;
    s_status.ptp_clock_readable = clock_readable;
    s_status.ptp_clock_running = clock_running;
    s_status.ptp_timestamp_resolution_ns = resolution_ns;
    s_status.rx_hw_timestamp_all_enabled = ts4all_enabled;
    portEXIT_CRITICAL(&s_eth_lock);

    ESP_LOGI(TAG,
             "EMAC PTP diagnostic: enabled=1 resolution=%" PRIu32
             " ns readable=%d running=%d",
             resolution_ns,
             clock_readable ? 1 : 0,
             clock_running ? 1 : 0);

    if (!clock_readable) {
        ESP_LOGW(TAG,
                 "EMAC PTP clock read failed: first=%s second=%s",
                 esp_err_to_name(first_err),
                 esp_err_to_name(second_err));
    } else if (!clock_running) {
        ESP_LOGW(TAG, "EMAC PTP clock did not advance during diagnostic probe");
    }
#else
    portENTER_CRITICAL(&s_eth_lock);
    s_status.ptp_supported = false;
    portEXIT_CRITICAL(&s_eth_lock);
    ESP_LOGW(TAG, "EMAC IEEE-1588/PTP capability is not available in this build");
#endif
}

static void eth_event_handler(void *arg,
                              esp_event_base_t event_base,
                              int32_t event_id,
                              void *event_data)
{
    (void)arg;
    (void)event_base;
    (void)event_data;

    if (event_id == ETHERNET_EVENT_CONNECTED) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.link_up = true;
        portEXIT_CRITICAL(&s_eth_lock);

        ESP_LOGI(TAG, "Ethernet link up");
        return;
    }

    if (event_id == ETHERNET_EVENT_DISCONNECTED) {
        portENTER_CRITICAL(&s_eth_lock);

        s_status.link_up = false;
        s_status.ipv4_ready = false;
        s_status.ipv4_address = 0U;
        s_status.ipv4_netmask = 0U;
        s_status.ipv4_gateway = 0U;

        portEXIT_CRITICAL(&s_eth_lock);

        app_state_set_ipv4_ready(false);

        if (s_eth_events != NULL) {
            xEventGroupClearBits(s_eth_events, ETH_IP_READY_BIT);
        }

        ESP_LOGW(TAG, "Ethernet link down");
        return;
    }

    if (event_id == ETHERNET_EVENT_START) {
        ESP_LOGI(TAG, "Ethernet driver started");
        return;
    }

    if (event_id == ETHERNET_EVENT_STOP) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.started = false;
        s_status.link_up = false;
        s_status.ipv4_ready = false;
        portEXIT_CRITICAL(&s_eth_lock);

        app_state_set_ipv4_ready(false);

        if (s_eth_events != NULL) {
            xEventGroupClearBits(s_eth_events, ETH_IP_READY_BIT);
        }

        ESP_LOGW(TAG, "Ethernet driver stopped");
    }
}

static void got_ip_event_handler(void *arg,
                                 esp_event_base_t event_base,
                                 int32_t event_id,
                                 void *event_data)
{
    (void)arg;
    (void)event_base;
    (void)event_id;

    const ip_event_got_ip_t *got_ip =
        (const ip_event_got_ip_t *)event_data;

    if (got_ip == NULL) {
        return;
    }

    portENTER_CRITICAL(&s_eth_lock);

    s_status.ipv4_ready = true;
    s_status.ipv4_address = got_ip->ip_info.ip.addr;
    s_status.ipv4_netmask = got_ip->ip_info.netmask.addr;
    s_status.ipv4_gateway = got_ip->ip_info.gw.addr;

    portEXIT_CRITICAL(&s_eth_lock);

    app_state_set_ipv4_ready(true);

    if (s_eth_events != NULL) {
        xEventGroupSetBits(s_eth_events, ETH_IP_READY_BIT);
    }

    ESP_LOGI(TAG,
             "DHCP IPv4 acquired: " IPSTR,
             IP2STR(&got_ip->ip_info.ip));
}

esp_err_t eth_service_init(void)
{
    if (s_status.initialized) {
        return ESP_OK;
    }

    if (s_eth_events == NULL) {
        s_eth_events = xEventGroupCreate();

        if (s_eth_events == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    const eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();

    eth_esp32_emac_config_t emac_config =
        ETH_ESP32_EMAC_DEFAULT_CONFIG();

    emac_config.smi_gpio.mdc_num = APP_ETH_MDC_GPIO;
    emac_config.smi_gpio.mdio_num = APP_ETH_MDIO_GPIO;

    esp_eth_mac_t *mac =
        esp_eth_mac_new_esp32(&emac_config, &mac_config);

    if (mac == NULL) {
        return ESP_ERR_NO_MEM;
    }

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();

    phy_config.phy_addr = APP_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = APP_ETH_PHY_RESET_GPIO;

    esp_eth_phy_t *phy = esp_eth_phy_new_ip101(&phy_config);

    if (phy == NULL) {
        return ESP_ERR_NO_MEM;
    }

    const esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);

    ESP_RETURN_ON_ERROR(
        esp_eth_driver_install(&eth_config, &s_eth_handle),
        TAG,
        "install Ethernet driver");

    ESP_RETURN_ON_ERROR(
        esp_eth_get_mac_instance(s_eth_handle, &s_eth_mac),
        TAG,
        "get Ethernet MAC instance");

    const esp_netif_config_t netif_config =
        ESP_NETIF_DEFAULT_ETH();

    s_eth_netif = esp_netif_new(&netif_config);

    if (s_eth_netif == NULL) {
        return ESP_ERR_NO_MEM;
    }

    const esp_eth_netif_glue_handle_t glue =
        esp_eth_new_netif_glue(s_eth_handle);

    if (glue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ESP_RETURN_ON_ERROR(
        esp_netif_attach(s_eth_netif, glue),
        TAG,
        "attach Ethernet netif");

    /* Phase 6C.5A: preserve the stock Ethernet esp-netif driver
     * configuration while replacing only TX with the observe-only NTP
     * hardware timestamp dispatcher. */
    const esp_netif_driver_ifconfig_t tx_probe_driver_config = {
        .handle = s_eth_handle,
        .transmit = eth_ntp_tx_probe_transmit,
        .transmit_wrap = NULL,
        .driver_free_rx_buffer = eth_tx_probe_l2_free,
        .driver_set_mac_filter = eth_tx_probe_set_mac_filter,
    };

    ESP_RETURN_ON_ERROR(
        esp_netif_set_driver_config(s_eth_netif, &tx_probe_driver_config),
        TAG,
        "install NTP TX hardware timestamp probe");

    /* Phase 6C.4A: preserve the normal esp-netif receive path while
     * observing the EMAC-provided RX descriptor timestamp. */
    ESP_RETURN_ON_ERROR(
        esp_eth_update_input_path_info(s_eth_handle,
                                       eth_input_to_netif_with_timestamp,
                                       s_eth_netif),
        TAG,
        "install timestamp-aware Ethernet input path");

    ESP_RETURN_ON_ERROR(
        esp_event_handler_register(ETH_EVENT,
                                   ESP_EVENT_ANY_ID,
                                   &eth_event_handler,
                                   NULL),
        TAG,
        "register Ethernet event handler");

    ESP_RETURN_ON_ERROR(
        esp_event_handler_register(IP_EVENT,
                                   IP_EVENT_ETH_GOT_IP,
                                   &got_ip_event_handler,
                                   NULL),
        TAG,
        "register IPv4 event handler");

    uint8_t mac_address[6] = {0};

    ESP_RETURN_ON_ERROR(
        esp_eth_ioctl(s_eth_handle,
                      ETH_CMD_G_MAC_ADDR,
                      mac_address),
        TAG,
        "read Ethernet MAC address");

    portENTER_CRITICAL(&s_eth_lock);

    memset(&s_status, 0, sizeof(s_status));
    memset(s_ntp_rx_queue, 0, sizeof(s_ntp_rx_queue));
    s_ntp_rx_queue_next = 0U;
    s_ntp_rx_queue_sequence = 0U;
#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
    memset(&s_ntp_tx_probe, 0, sizeof(s_ntp_tx_probe));
#endif

    s_status.initialized = true;
#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
    s_status.ptp_supported = true;
#endif
    memcpy(s_status.mac, mac_address, sizeof(s_status.mac));

    portEXIT_CRITICAL(&s_eth_lock);

    ESP_LOGI(TAG,
             "IP101 initialized: PHY=%d MDC=%d MDIO=%d RESET=%d "
             "MAC=%02x:%02x:%02x:%02x:%02x:%02x",
             APP_ETH_PHY_ADDR,
             APP_ETH_MDC_GPIO,
             APP_ETH_MDIO_GPIO,
             APP_ETH_PHY_RESET_GPIO,
             mac_address[0],
             mac_address[1],
             mac_address[2],
             mac_address[3],
             mac_address[4],
             mac_address[5]);

    return ESP_OK;
}

esp_err_t eth_service_start(void)
{
    if (!s_status.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (s_status.started) {
        return ESP_OK;
    }

    ESP_RETURN_ON_ERROR(
        esp_eth_start(s_eth_handle),
        TAG,
        "start Ethernet driver");

    portENTER_CRITICAL(&s_eth_lock);
    s_status.started = true;
    portEXIT_CRITICAL(&s_eth_lock);

    /* Phase 6C.2: enable/probe the EMAC PTP engine. */
    eth_ptp_probe();

#ifdef SOC_EMAC_IEEE1588V2_SUPPORTED
    eth_service_status_t status_snapshot = {0};
    (void)eth_service_get_status(&status_snapshot);

    if (status_snapshot.ptp_enabled &&
        status_snapshot.ptp_clock_readable &&
        status_snapshot.ptp_clock_running &&
        s_ptp_correlation_task == NULL) {
        const BaseType_t task_result = xTaskCreate(
            eth_ptp_correlation_task,
            "eth_ptp_corr",
            4096U,
            NULL,
            5U,
            &s_ptp_correlation_task);

        if (task_result != pdPASS) {
            s_ptp_correlation_task = NULL;
            ESP_LOGW(TAG, "Unable to start passive PTP correlation task");
        } else {
            ESP_LOGI(TAG,
                     "Passive PTP/UTC correlation enabled: period=%" PRIu32 " ms",
                     (uint32_t)ETH_PTP_CORRELATION_PERIOD_MS);
        }
    }
#endif

    return ESP_OK;
}

void eth_service_wait_for_ip(void)
{
    if (s_eth_events == NULL) {
        ESP_LOGE(TAG, "Ethernet event group is unavailable");
        return;
    }

    while (true) {
        const EventBits_t bits = xEventGroupWaitBits(
            s_eth_events,
            ETH_IP_READY_BIT,
            pdFALSE,
            pdFALSE,
            pdMS_TO_TICKS(APP_ETH_WAIT_RETRY_MS));

        if ((bits & ETH_IP_READY_BIT) != 0U) {
            return;
        }

        ESP_LOGI(TAG, "Waiting for Ethernet DHCP IPv4 address");
        vTaskDelay(pdMS_TO_TICKS(1U));
    }
}

bool eth_service_take_ntp_rx_timestamp(uint32_t client_ipv4,
                                       uint16_t client_port,
                                       eth_service_ntp_rx_timestamp_t *out_timestamp)
{
#ifndef SOC_EMAC_IEEE1588V2_SUPPORTED
    (void)client_ipv4;
    (void)client_port;
    (void)out_timestamp;
    return false;
#else
    if (out_timestamp == NULL || s_eth_mac == NULL) {
        return false;
    }

    eth_mac_time_t rx_ptp = {0};
    bool found = false;

    portENTER_CRITICAL(&s_eth_lock);
    /* Oldest matching entry wins. With a 16-entry queue this bounded scan is
     * short and prevents two clients from stealing one another's timestamps. */
    uint32_t best_index = 0U;
    uint32_t best_sequence = UINT32_MAX;
    for (uint32_t index = 0U; index < ETH_NTP_RX_QUEUE_SIZE; index++) {
        const eth_ntp_rx_queue_entry_t *entry = &s_ntp_rx_queue[index];
        if (entry->valid && entry->client_ipv4 == client_ipv4 &&
            entry->client_port == client_port && entry->sequence < best_sequence) {
            best_index = index;
            best_sequence = entry->sequence;
            found = true;
        }
    }
    if (found) {
        rx_ptp = s_ntp_rx_queue[best_index].ptp_time;
        s_ntp_rx_queue[best_index].valid = false;
        s_status.rx_hw_queue_matches++;
    }
    if (!found) {
        s_status.rx_hw_queue_misses++;
    }
    portEXIT_CRITICAL(&s_eth_lock);

    if (!found) {
        return false;
    }

    clock_ntp_timestamp_t utc_before = {0};
    clock_ntp_timestamp_t utc_after = {0};
    eth_mac_time_t ptp_now = {0};

    if (!clock_discipline_get_ntp_timestamp(&utc_before) ||
        esp_eth_mac_get_ptp_time(s_eth_mac, &ptp_now) != ESP_OK ||
        !clock_discipline_get_ntp_timestamp(&utc_after)) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.rx_hw_map_failures++;
        portEXIT_CRITICAL(&s_eth_lock);
        return false;
    }

    const uint64_t utc_before_ns = ntp_timestamp_to_ns(&utc_before);
    const uint64_t utc_after_ns = ntp_timestamp_to_ns(&utc_after);
    const uint64_t ptp_now_ns = ptp_timestamp_to_ns(&ptp_now);
    const uint64_t rx_ptp_ns = ptp_timestamp_to_ns(&rx_ptp);

    if (utc_after_ns < utc_before_ns || ptp_now_ns < rx_ptp_ns) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.rx_hw_map_failures++;
        portEXIT_CRITICAL(&s_eth_lock);
        return false;
    }

    const uint64_t bracket_ns = utc_after_ns - utc_before_ns;
    const uint64_t utc_mid_ns = utc_before_ns + bracket_ns / 2ULL;
    const uint64_t ptp_age_ns = ptp_now_ns - rx_ptp_ns;

    int64_t rate_ppb = 0;
    int64_t correlation_last_us = 0;
    uint32_t correlation_samples = 0U;
    bool correlation_valid = false;
    portENTER_CRITICAL(&s_eth_lock);
    correlation_valid = s_status.ptp_correlation_valid;
    correlation_samples = s_status.ptp_correlation_samples;
    rate_ppb = s_status.ptp_utc_estimated_rate_ppb;
    correlation_last_us = s_ptp_correlation_last_monotonic_us;
    portEXIT_CRITICAL(&s_eth_lock);

    const int64_t now_us = esp_timer_get_time();
    if (!correlation_valid || correlation_samples < 2U ||
        correlation_last_us <= 0 || now_us < correlation_last_us ||
        (now_us - correlation_last_us) > ETH_PTP_CORRELATION_MAX_AGE_US ||
        bracket_ns > ETH_PTP_LOCAL_MAP_MAX_BRACKET_NS) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.rx_hw_map_failures++;
        portEXIT_CRITICAL(&s_eth_lock);
        return false;
    }

    const int64_t denominator = 1000000000LL + rate_ppb;
    if (denominator <= 0) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.rx_hw_map_failures++;
        portEXIT_CRITICAL(&s_eth_lock);
        return false;
    }

    /* ESP32-P4 is a 32-bit RISC-V target and its toolchain does not provide
     * __int128.  Compute round(ptp_age_ns * 1e9 / denominator) without a
     * potentially overflowing 64-bit product by splitting quotient/remainder. */
    const uint64_t denominator_u = (uint64_t)denominator;
    const uint64_t age_quotient = ptp_age_ns / denominator_u;
    const uint64_t age_remainder = ptp_age_ns % denominator_u;
    const uint64_t utc_age_ns =
        age_quotient * 1000000000ULL +
        (age_remainder * 1000000000ULL + denominator_u / 2ULL) / denominator_u;
    if (utc_age_ns > utc_mid_ns) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.rx_hw_map_failures++;
        portEXIT_CRITICAL(&s_eth_lock);
        return false;
    }

    const uint64_t mapped_ns = utc_mid_ns - utc_age_ns;
    const uint64_t seconds = mapped_ns / 1000000000ULL;
    const uint64_t nanoseconds = mapped_ns % 1000000000ULL;
    if (seconds > UINT32_MAX) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.rx_hw_map_failures++;
        portEXIT_CRITICAL(&s_eth_lock);
        return false;
    }

    out_timestamp->seconds = (uint32_t)seconds;
    /* nanoseconds < 1e9, so nanoseconds * 2^32 fits in uint64_t. */
    out_timestamp->fraction =
        (uint32_t)(((nanoseconds << 32) + 500000000ULL) / 1000000000ULL);
    out_timestamp->mapping_bracket_ns = bracket_ns > UINT32_MAX ? UINT32_MAX : (uint32_t)bracket_ns;
    out_timestamp->mapping_age_us = ptp_age_ns / 1000ULL > UINT32_MAX ? UINT32_MAX :
                                    (uint32_t)(ptp_age_ns / 1000ULL);

    portENTER_CRITICAL(&s_eth_lock);
    s_status.rx_hw_map_successes++;
    s_status.rx_hw_last_map_bracket_ns = out_timestamp->mapping_bracket_ns;
    s_status.rx_hw_last_map_age_us = out_timestamp->mapping_age_us;
    portEXIT_CRITICAL(&s_eth_lock);
    return true;
#endif
}

bool eth_service_get_status(eth_service_status_t *out_status)
{
    if (out_status == NULL) {
        return false;
    }

    portENTER_CRITICAL(&s_eth_lock);
    *out_status = s_status;
    portEXIT_CRITICAL(&s_eth_lock);

    return true;
}