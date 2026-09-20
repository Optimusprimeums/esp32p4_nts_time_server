#include "ntp_peer_monitor.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "clock_discipline.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static const char *TAG = "NTP_PEER";

#define NTP_PORT                         123
#define NTP_PACKET_SIZE                  48U
#define NTP_VERSION                      4U
#define NTP_MODE_CLIENT                  3U
#define NTP_MODE_SERVER                  4U
#define NTP_PEER_TASK_STACK_SIZE         12288U
#define NTP_PEER_TASK_PRIORITY           4U
#define NTP_PEER_START_DELAY_MS          2000U
#define NTP_PEER_DIVERGENT_NS            10000000LL
#define NTP_PEER_DEGRADED_DELAY_NS       100000000LL
#define NTP_PEER_DEGRADED_JITTER_NS      5000000LL
#define NTP_PEER_UNREACHABLE_FAILURES    3U
#define NTP_PEER_ROLLING_WINDOW          16U
#define NTP_PEER_CONFIG_CHECK_MS         1000U

typedef struct {
    int sock;
    bool active;
    bool completed;
    struct sockaddr_in address;
    clock_ntp_timestamp_t t1;
    int64_t deadline_us;
} poll_context_t;

typedef struct {
    int64_t offset[NTP_PEER_ROLLING_WINDOW];
    int64_t delay[NTP_PEER_ROLLING_WINDOW];
    uint32_t count;
    uint32_t next;
    uint64_t last_server_t3;
    bool last_server_t3_valid;
    int64_t last_success_us;
    bool config_valid;
    bool enabled;
    char server[APP_NTP_PEER_SERVER_MAX_LENGTH + 1U];
} peer_runtime_t;

static SemaphoreHandle_t s_lock;
static TaskHandle_t s_task;
static bool s_initialized;
static bool s_running;
static ntp_peer_monitor_status_t s_status;
static peer_runtime_t s_runtime[APP_NTP_PEER_MAX_COUNT];

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint64_t timestamp_to_fixed(clock_ntp_timestamp_t t)
{
    return ((uint64_t)t.seconds << 32) | (uint64_t)t.fraction;
}

static int64_t fixed_delta_ns(uint64_t a, uint64_t b)
{
    /* Integer conversion from signed NTP 32.32 delta to nanoseconds. */
    const int64_t delta = (int64_t)(a - b);
    const int64_t whole_seconds = delta / INT64_C(4294967296);
    const int64_t fractional = delta % INT64_C(4294967296);
    return whole_seconds * INT64_C(1000000000) +
           (fractional * INT64_C(1000000000)) / INT64_C(4294967296);
}

static int64_t abs_i64(int64_t value)
{
    if (value == INT64_MIN) return INT64_MAX;
    return value < 0 ? -value : value;
}

static uint64_t isqrt_u64(uint64_t value)
{
    uint64_t result = 0U;
    uint64_t bit = UINT64_C(1) << 62;
    while (bit > value) bit >>= 2;
    while (bit != 0U) {
        if (value >= result + bit) {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    return result;
}

static int64_t div_round_i64(int64_t numerator, int64_t denominator)
{
    if (denominator <= 0) return 0;
    if (numerator >= 0) return (numerator + denominator / 2) / denominator;
    return -(((-numerator) + denominator / 2) / denominator);
}

static bool lock_status(void)
{
    return s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE;
}

static void unlock_status(void)
{
    (void)xSemaphoreGive(s_lock);
}

const char *ntp_peer_monitor_health_name(ntp_peer_health_t health)
{
    switch (health) {
    case NTP_PEER_HEALTH_DISABLED: return "DISABLED";
    case NTP_PEER_HEALTH_UNKNOWN: return "UNKNOWN";
    case NTP_PEER_HEALTH_HEALTHY: return "HEALTHY";
    case NTP_PEER_HEALTH_DEGRADED: return "DEGRADED";
    case NTP_PEER_HEALTH_UNREACHABLE: return "UNREACHABLE";
    case NTP_PEER_HEALTH_DIVERGENT: return "DIVERGENT";
    case NTP_PEER_HEALTH_KOD: return "KOD";
    case NTP_PEER_HEALTH_INVALID: return "INVALID";
    default: return "UNKNOWN";
    }
}

static void reference_id_to_text(const uint8_t *packet, uint8_t stratum, char out[9])
{
    if (stratum <= 1U) {
        for (size_t i = 0; i < 4U; ++i) {
            const uint8_t c = packet[12U + i];
            out[i] = (c >= 0x20U && c <= 0x7eU) ? (char)c : '.';
        }
        out[4] = '\0';
        return;
    }
    (void)snprintf(out, 9U, "%08" PRIX32, read_be32(packet + 12U));
}

static void reset_peer_slot(size_t index, bool configured, const char *server)
{
    memset(&s_runtime[index], 0, sizeof(s_runtime[index]));
    s_runtime[index].config_valid = true;
    s_runtime[index].enabled = configured;
    if (server != NULL) {
        (void)snprintf(s_runtime[index].server, sizeof(s_runtime[index].server), "%s", server);
    }

    if (!lock_status()) return;
    memset(&s_status.peers[index], 0, sizeof(s_status.peers[index]));
    s_status.peers[index].configured = configured;
    s_status.peers[index].health = configured ? NTP_PEER_HEALTH_UNKNOWN : NTP_PEER_HEALTH_DISABLED;
    if (server != NULL) {
        (void)snprintf(s_status.peers[index].server, sizeof(s_status.peers[index].server), "%s", server);
    }
    unlock_status();
}

static bool sync_config(const device_config_snapshot_t *config)
{
    bool changed = false;
    uint32_t configured_count = 0U;

    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        const bool configured = config->ntp_peers[i].enabled && config->ntp_peers[i].server[0] != '\0';
        if (configured) configured_count++;
        if (!s_runtime[i].config_valid || s_runtime[i].enabled != configured ||
            strcmp(s_runtime[i].server, config->ntp_peers[i].server) != 0) {
            reset_peer_slot(i, configured, config->ntp_peers[i].server);
            changed = true;
        }
    }

    if (lock_status()) {
        if (s_status.enabled != config->ntp_peer_monitor_enabled ||
            s_status.poll_interval_seconds != config->ntp_peer_poll_interval_seconds ||
            s_status.response_timeout_ms != config->ntp_peer_response_timeout_ms) changed = true;
        s_status.enabled = config->ntp_peer_monitor_enabled;
        s_status.poll_interval_seconds = config->ntp_peer_poll_interval_seconds;
        s_status.response_timeout_ms = config->ntp_peer_response_timeout_ms;
        s_status.configured_peers = configured_count;
        unlock_status();
    }
    return changed;
}

static bool resolve_peer(const char *server, struct sockaddr_in *out_addr)
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *result = NULL;
    const int rc = getaddrinfo(server, "123", &hints, &result);
    if (rc != 0 || result == NULL) {
        if (result != NULL) freeaddrinfo(result);
        return false;
    }
    memcpy(out_addr, result->ai_addr, sizeof(*out_addr));
    out_addr->sin_port = htons(NTP_PORT);
    freeaddrinfo(result);
    return true;
}

static void update_failure(size_t index, ntp_peer_health_t requested,
                           bool timeout, bool dns, bool rejected, bool duplicate)
{
    if (!lock_status()) return;
    ntp_peer_status_t *peer = &s_status.peers[index];
    peer->reachability = (uint8_t)(peer->reachability << 1);
    peer->failed_polls++;
    peer->consecutive_failures++;
    if (timeout) peer->timeout_failures++;
    if (dns) peer->dns_failures++;
    if (rejected) peer->rejected_responses++;
    if (duplicate) peer->duplicate_responses++;
    if (requested == NTP_PEER_HEALTH_KOD || requested == NTP_PEER_HEALTH_INVALID) {
        peer->health = requested;
    } else if (peer->consecutive_failures >= NTP_PEER_UNREACHABLE_FAILURES) {
        peer->health = NTP_PEER_HEALTH_UNREACHABLE;
    } else {
        peer->health = NTP_PEER_HEALTH_DEGRADED;
    }
    unlock_status();
}

static void compute_rolling_stats(size_t index, ntp_peer_status_t *peer)
{
    peer_runtime_t *rt = &s_runtime[index];
    if (rt->count == 0U) return;

    int64_t min_offset = rt->offset[0];
    int64_t max_offset = rt->offset[0];
    int64_t min_delay = rt->delay[0];
    int64_t offset_sum = 0;
    int64_t delay_sum = 0;
    uint64_t offset_sq_sum = 0U;
    uint64_t diff_sq_sum = 0U;

    for (uint32_t i = 0; i < rt->count; ++i) {
        const int64_t o = rt->offset[i];
        const int64_t d = rt->delay[i];
        offset_sum += o;
        delay_sum += d;
        if (o < min_offset) min_offset = o;
        if (o > max_offset) max_offset = o;
        if (d < min_delay) min_delay = d;

        const uint64_t ao = (uint64_t)abs_i64(o);
        const uint64_t osq = (ao != 0U && ao > UINT64_MAX / ao) ? UINT64_MAX : ao * ao;
        offset_sq_sum = UINT64_MAX - offset_sq_sum < osq ? UINT64_MAX : offset_sq_sum + osq;

        if (i > 0U) {
            const int64_t diff = o - rt->offset[i - 1U];
            const uint64_t ad = (uint64_t)abs_i64(diff);
            const uint64_t dsq = (ad != 0U && ad > UINT64_MAX / ad) ? UINT64_MAX : ad * ad;
            diff_sq_sum = UINT64_MAX - diff_sq_sum < dsq ? UINT64_MAX : diff_sq_sum + dsq;
        }
    }

    const int64_t n = (int64_t)rt->count;
    peer->rolling_samples = rt->count;
    peer->min_offset_ns = min_offset;
    peer->max_offset_ns = max_offset;
    peer->mean_offset_ns = div_round_i64(offset_sum, n);
    peer->rms_offset_ns = (int64_t)isqrt_u64(offset_sq_sum / (uint64_t)rt->count);
    peer->min_delay_ns = min_delay;
    peer->mean_delay_ns = div_round_i64(delay_sum, n);
    peer->jitter_ns = rt->count > 1U
                          ? (int64_t)isqrt_u64(diff_sq_sum / (uint64_t)(rt->count - 1U))
                          : 0;
}

static void update_success(size_t index, const uint8_t *packet, uint64_t server_t3,
                           int64_t offset_ns, int64_t delay_ns)
{
    peer_runtime_t *rt = &s_runtime[index];
    rt->offset[rt->next] = offset_ns;
    rt->delay[rt->next] = delay_ns;
    rt->next = (rt->next + 1U) % NTP_PEER_ROLLING_WINDOW;
    if (rt->count < NTP_PEER_ROLLING_WINDOW) rt->count++;

    /* Keep the rolling arrays in chronological order after wrap. */
    if (rt->count == NTP_PEER_ROLLING_WINDOW && rt->next != 0U) {
        int64_t ordered_offset[NTP_PEER_ROLLING_WINDOW];
        int64_t ordered_delay[NTP_PEER_ROLLING_WINDOW];
        for (uint32_t i = 0; i < NTP_PEER_ROLLING_WINDOW; ++i) {
            const uint32_t src = (rt->next + i) % NTP_PEER_ROLLING_WINDOW;
            ordered_offset[i] = rt->offset[src];
            ordered_delay[i] = rt->delay[src];
        }
        memcpy(rt->offset, ordered_offset, sizeof(ordered_offset));
        memcpy(rt->delay, ordered_delay, sizeof(ordered_delay));
        rt->next = 0U;
    }

    rt->last_server_t3 = server_t3;
    rt->last_server_t3_valid = true;
    rt->last_success_us = esp_timer_get_time();

    if (!lock_status()) return;
    ntp_peer_status_t *peer = &s_status.peers[index];
    peer->reachability = (uint8_t)((peer->reachability << 1) | 1U);
    peer->successful_polls++;
    peer->consecutive_failures = 0U;
    peer->samples++;
    peer->stratum = packet[1];
    peer->leap = (uint8_t)(packet[0] >> 6);
    peer->root_delay_16_16 = (int32_t)read_be32(packet + 4U);
    peer->root_dispersion_16_16 = read_be32(packet + 8U);
    reference_id_to_text(packet, peer->stratum, peer->reference_id);
    peer->offset_ns = offset_ns;
    peer->delay_ns = delay_ns;
    peer->last_success_age_seconds = 0U;
    compute_rolling_stats(index, peer);
    peer->health = (delay_ns > NTP_PEER_DEGRADED_DELAY_NS ||
                    peer->jitter_ns > NTP_PEER_DEGRADED_JITTER_NS)
                       ? NTP_PEER_HEALTH_DEGRADED
                       : NTP_PEER_HEALTH_HEALTHY;
    unlock_status();
}

static bool begin_poll(size_t index, const device_config_ntp_peer_t *config,
                       uint32_t timeout_ms, poll_context_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->sock = -1;
    if (!resolve_peer(config->server, &ctx->address)) {
        ESP_LOGW(TAG, "Peer %u DNS resolution failed", (unsigned)index);
        update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, true, false, false);
        return false;
    }

    ctx->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->sock < 0) {
        update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
        return false;
    }

    uint8_t request[NTP_PACKET_SIZE] = {0};
    request[0] = (uint8_t)((NTP_VERSION << 3) | NTP_MODE_CLIENT);
    if (!clock_discipline_get_ntp_timestamp(&ctx->t1)) {
        close(ctx->sock);
        ctx->sock = -1;
        update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
        return false;
    }
    write_be32(request + 40U, ctx->t1.seconds);
    write_be32(request + 44U, ctx->t1.fraction);

    const ssize_t sent = sendto(ctx->sock, request, sizeof(request), 0,
                                (const struct sockaddr *)&ctx->address, sizeof(ctx->address));
    if (sent != (ssize_t)sizeof(request)) {
        close(ctx->sock);
        ctx->sock = -1;
        update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
        return false;
    }

    ctx->active = true;
    ctx->deadline_us = esp_timer_get_time() + (int64_t)timeout_ms * 1000LL;
    return true;
}

static void finish_context(poll_context_t *ctx)
{
    if (ctx->sock >= 0) close(ctx->sock);
    ctx->sock = -1;
    ctx->active = false;
    ctx->completed = true;
}

static void process_response(size_t index, poll_context_t *ctx)
{
    uint8_t response[256];
    struct sockaddr_in source = {0};
    socklen_t source_len = sizeof(source);
    const ssize_t received = recvfrom(ctx->sock, response, sizeof(response), 0,
                                      (struct sockaddr *)&source, &source_len);
    clock_ntp_timestamp_t t4;
    const bool t4_valid = clock_discipline_get_ntp_timestamp(&t4);

    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
            finish_context(ctx);
        }
        return;
    }
    finish_context(ctx);

    if (!t4_valid || received < (ssize_t)NTP_PACKET_SIZE ||
        source.sin_addr.s_addr != ctx->address.sin_addr.s_addr ||
        source.sin_port != ctx->address.sin_port) {
        update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, false);
        return;
    }

    const uint8_t li = response[0] >> 6;
    const uint8_t version = (response[0] >> 3) & 0x07U;
    const uint8_t mode = response[0] & 0x07U;
    const uint8_t stratum = response[1];

    if (stratum == 0U) {
        char kod[9] = {0};
        reference_id_to_text(response, 0U, kod);
        if (lock_status()) {
            s_status.peers[index].kod_responses++;
            (void)snprintf(s_status.peers[index].reference_id,
                           sizeof(s_status.peers[index].reference_id), "%s", kod);
            unlock_status();
        }
        ESP_LOGW(TAG, "Peer %u returned KoD %.4s", (unsigned)index, kod);
        update_failure(index, NTP_PEER_HEALTH_KOD, false, false, true, false);
        return;
    }

    if (version < 3U || mode != NTP_MODE_SERVER || li == 3U || stratum > 15U ||
        read_be32(response + 24U) != ctx->t1.seconds ||
        read_be32(response + 28U) != ctx->t1.fraction ||
        (read_be32(response + 32U) == 0U && read_be32(response + 36U) == 0U) ||
        (read_be32(response + 40U) == 0U && read_be32(response + 44U) == 0U)) {
        update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, false);
        return;
    }

    const uint64_t f1 = timestamp_to_fixed(ctx->t1);
    const uint64_t f2 = ((uint64_t)read_be32(response + 32U) << 32) | read_be32(response + 36U);
    const uint64_t f3 = ((uint64_t)read_be32(response + 40U) << 32) | read_be32(response + 44U);
    const uint64_t f4 = timestamp_to_fixed(t4);

    if (s_runtime[index].last_server_t3_valid && s_runtime[index].last_server_t3 == f3) {
        update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, true);
        return;
    }

    const int64_t a = fixed_delta_ns(f2, f1);
    const int64_t b = fixed_delta_ns(f3, f4);
    const int64_t offset_ns = (a / 2) + (b / 2) + ((a % 2) + (b % 2)) / 2;
    const int64_t delay_ns = fixed_delta_ns(f4, f1) - fixed_delta_ns(f3, f2);
    if (delay_ns < 0) {
        update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, false);
        return;
    }
    update_success(index, response, f3, offset_ns, delay_ns);
}

static void poll_all_peers(const device_config_snapshot_t *config)
{
    poll_context_t contexts[APP_NTP_PEER_MAX_COUNT];
    memset(contexts, 0, sizeof(contexts));
    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) contexts[i].sock = -1;

    uint32_t pending = 0U;
    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        if (config->ntp_peers[i].enabled && config->ntp_peers[i].server[0] != '\0' &&
            begin_poll(i, &config->ntp_peers[i], config->ntp_peer_response_timeout_ms, &contexts[i])) {
            pending++;
        }
    }

    while (pending > 0U) {
        fd_set readfds;
        FD_ZERO(&readfds);
        int maxfd = -1;
        int64_t nearest_deadline = INT64_MAX;
        const int64_t now_us = esp_timer_get_time();

        for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
            if (!contexts[i].active) continue;
            if (now_us >= contexts[i].deadline_us) {
                update_failure(i, NTP_PEER_HEALTH_DEGRADED, true, false, false, false);
                finish_context(&contexts[i]);
                pending--;
                continue;
            }
            FD_SET(contexts[i].sock, &readfds);
            if (contexts[i].sock > maxfd) maxfd = contexts[i].sock;
            if (contexts[i].deadline_us < nearest_deadline) nearest_deadline = contexts[i].deadline_us;
        }
        if (pending == 0U || maxfd < 0) break;

        int64_t wait_us = nearest_deadline - esp_timer_get_time();
        if (wait_us < 0) wait_us = 0;
        struct timeval tv = {
            .tv_sec = (time_t)(wait_us / 1000000LL),
            .tv_usec = (suseconds_t)(wait_us % 1000000LL),
        };
        const int rc = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
                if (contexts[i].active) {
                    update_failure(i, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
                    finish_context(&contexts[i]);
                    pending--;
                }
            }
            break;
        }
        if (rc == 0) continue;
        for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
            if (contexts[i].active && FD_ISSET(contexts[i].sock, &readfds)) {
                process_response(i, &contexts[i]);
                if (contexts[i].completed) pending--;
            }
        }
    }
}

static void refresh_aggregate_health(void)
{
    if (!lock_status()) return;
    int64_t min_offset = 0;
    int64_t max_offset = 0;
    bool have_offset = false;
    uint32_t sampled = 0U;
    uint32_t healthy = 0U;
    const int64_t now_us = esp_timer_get_time();

    s_status.best_observed_peer_valid = false;
    s_status.best_observed_peer_index = 0U;
    int64_t best_score = INT64_MAX;

    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        ntp_peer_status_t *peer = &s_status.peers[i];
        if (!peer->configured) continue;
        if (s_runtime[i].last_success_us > 0) {
            const int64_t age_us = now_us - s_runtime[i].last_success_us;
            peer->last_success_age_seconds = age_us > 0 ? (uint32_t)(age_us / 1000000LL) : 0U;
        }
        if (peer->samples == 0U || peer->health == NTP_PEER_HEALTH_UNREACHABLE ||
            peer->health == NTP_PEER_HEALTH_KOD || peer->health == NTP_PEER_HEALTH_INVALID) continue;

        sampled++;
        if (!have_offset) {
            min_offset = max_offset = peer->offset_ns;
            have_offset = true;
        } else {
            if (peer->offset_ns < min_offset) min_offset = peer->offset_ns;
            if (peer->offset_ns > max_offset) max_offset = peer->offset_ns;
        }

        /* Telemetry-only observation score: |offset| + jitter + delay/4. */
        const int64_t offset_score = abs_i64(peer->offset_ns);
        const int64_t jitter_score = abs_i64(peer->jitter_ns);
        const int64_t delay_score = peer->delay_ns > 0 ? peer->delay_ns / 4 : 0;
        int64_t score = offset_score;
        score = score > INT64_MAX - jitter_score ? INT64_MAX : score + jitter_score;
        score = score > INT64_MAX - delay_score ? INT64_MAX : score + delay_score;
        if (!s_status.best_observed_peer_valid || score < best_score) {
            best_score = score;
            s_status.best_observed_peer_valid = true;
            s_status.best_observed_peer_index = (uint32_t)i;
        }
    }

    s_status.cross_peer_spread_valid = sampled >= 2U;
    s_status.cross_peer_spread_ns = sampled >= 2U ? max_offset - min_offset : 0;
    if (s_status.cross_peer_spread_valid && s_status.cross_peer_spread_ns > NTP_PEER_DIVERGENT_NS) {
        for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
            ntp_peer_status_t *peer = &s_status.peers[i];
            if (peer->configured && peer->samples > 0U &&
                peer->health != NTP_PEER_HEALTH_UNREACHABLE &&
                peer->health != NTP_PEER_HEALTH_KOD &&
                peer->health != NTP_PEER_HEALTH_INVALID) {
                peer->health = NTP_PEER_HEALTH_DIVERGENT;
            }
        }
    }
    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        if (s_status.peers[i].health == NTP_PEER_HEALTH_HEALTHY) healthy++;
    }
    s_status.healthy_peers = healthy;
    unlock_status();
}

static void monitor_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(NTP_PEER_START_DELAY_MS));

    for (;;) {
        device_config_snapshot_t config;
        if (device_config_get_snapshot(&config) != ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(NTP_PEER_CONFIG_CHECK_MS));
            continue;
        }
        (void)sync_config(&config);

        if (config.ntp_peer_monitor_enabled) {
            poll_all_peers(&config);
            if (lock_status()) {
                s_status.poll_cycles++;
                unlock_status();
            }
            refresh_aggregate_health();
        } else {
            refresh_aggregate_health();
        }

        const uint32_t interval = config.ntp_peer_poll_interval_seconds >= APP_NTP_PEER_POLL_MIN_SECONDS
                                      ? config.ntp_peer_poll_interval_seconds
                                      : APP_NTP_PEER_POLL_DEFAULT_SECONDS;
        uint32_t waited_ms = 0U;
        const uint32_t target_ms = config.ntp_peer_monitor_enabled ? interval * 1000U : NTP_PEER_CONFIG_CHECK_MS;
        while (waited_ms < target_ms) {
            const uint32_t slice = (target_ms - waited_ms) > NTP_PEER_CONFIG_CHECK_MS
                                       ? NTP_PEER_CONFIG_CHECK_MS : (target_ms - waited_ms);
            vTaskDelay(pdMS_TO_TICKS(slice));
            waited_ms += slice;

            device_config_snapshot_t latest;
            if (device_config_get_snapshot(&latest) == ESP_OK && sync_config(&latest)) break;
        }
    }
}

esp_err_t ntp_peer_monitor_start(void)
{
    if (s_running) return ESP_OK;
    if (!s_initialized) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) return ESP_ERR_NO_MEM;
        memset(&s_status, 0, sizeof(s_status));
        memset(s_runtime, 0, sizeof(s_runtime));
        s_status.initialized = true;
        s_initialized = true;
    }
    if (xTaskCreate(monitor_task, "ntp_peer", NTP_PEER_TASK_STACK_SIZE, NULL,
                    NTP_PEER_TASK_PRIORITY, &s_task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    s_running = true;
    if (lock_status()) {
        s_status.running = true;
        unlock_status();
    }
    ESP_LOGI(TAG, "Independent NTP peer monitor started (telemetry-only; no timing authority)");
    return ESP_OK;
}

bool ntp_peer_monitor_is_running(void)
{
    return s_running;
}

bool ntp_peer_monitor_get_status(ntp_peer_monitor_status_t *out_status)
{
    if (out_status == NULL || !s_initialized || !lock_status()) return false;
    *out_status = s_status;
    unlock_status();
    return true;
}
