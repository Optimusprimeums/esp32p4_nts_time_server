#include "nts_ntp_auth.h"

#include <string.h>

#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "nts_aes_siv.h"

#define NTP_HEADER_LEN                         48U
#define NTS_EF_UNIQUE_IDENTIFIER            0x0104U
#define NTS_EF_COOKIE                       0x0204U
#define NTS_EF_COOKIE_PLACEHOLDER           0x0304U
#define NTS_EF_AUTHENTICATOR                0x0404U
static portMUX_TYPE s_stats_lock = portMUX_INITIALIZER_UNLOCKED;
static nts_ntp_auth_stats_t s_stats;

static void stats_increment(uint32_t *counter)
{
    portENTER_CRITICAL(&s_stats_lock);
    (*counter)++;
    portEXIT_CRITICAL(&s_stats_lock);
}

void nts_ntp_auth_get_stats(nts_ntp_auth_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }

    portENTER_CRITICAL(&s_stats_lock);
    *stats = s_stats;
    portEXIT_CRITICAL(&s_stats_lock);
}

static uint8_t s_plaintext[NTS_NTP_MAX_PACKET_SIZE];
static uint8_t s_ciphertext[NTS_NTP_MAX_PACKET_SIZE];
static uint8_t s_auth_body[NTS_NTP_MAX_PACKET_SIZE];

static uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static void write_be16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static size_t round_up_4(size_t value)
{
    return (value + 3U) & ~(size_t)3U;
}

static bool is_nts_type(uint16_t type)
{
    return type == NTS_EF_UNIQUE_IDENTIFIER ||
           type == NTS_EF_COOKIE ||
           type == NTS_EF_COOKIE_PLACEHOLDER ||
           type == NTS_EF_AUTHENTICATOR;
}

bool nts_ntp_auth_request_present(const uint8_t *packet, size_t packet_len)
{
    if (packet == NULL || packet_len <= NTP_HEADER_LEN) {
        return false;
    }

    size_t offset = NTP_HEADER_LEN;

    while ((packet_len - offset) >= 4U) {
        const uint16_t type = read_be16(&packet[offset]);
        const uint16_t field_len = read_be16(&packet[offset + 2U]);

        if (is_nts_type(type)) {
            return true;
        }

        if (field_len < 4U ||
            (field_len & 0x03U) != 0U ||
            field_len > (packet_len - offset)) {
            return false;
        }

        offset += field_len;
    }

    return false;
}

static esp_err_t append_extension(
    uint8_t *packet,
    size_t capacity,
    size_t *offset,
    uint16_t type,
    const uint8_t *body,
    size_t body_len)
{
    if (packet == NULL || offset == NULL ||
        (body_len != 0U && body == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }

    const size_t field_len = 4U + body_len;

    if (field_len > UINT16_MAX ||
        (field_len & 0x03U) != 0U ||
        field_len > (capacity - *offset)) {
        return ESP_ERR_INVALID_SIZE;
    }

    write_be16(&packet[*offset], type);
    write_be16(&packet[*offset + 2U], (uint16_t)field_len);

    if (body_len != 0U) {
        memcpy(&packet[*offset + 4U], body, body_len);
    }

    *offset += field_len;
    return ESP_OK;
}

static esp_err_t verify_request_impl(
    const uint8_t *packet,
    size_t packet_len,
    nts_ntp_auth_context_t *context)
{
    if (packet == NULL || context == NULL ||
        packet_len < NTP_HEADER_LEN ||
        packet_len > NTS_NTP_MAX_PACKET_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(context, 0, sizeof(*context));

    const uint8_t *uid = NULL;
    size_t uid_len = 0U;
    const uint8_t *cookie = NULL;
    size_t cookie_len = 0U;
    size_t placeholder_lengths[NTS_NTP_MAX_PLACEHOLDERS];
    size_t placeholder_count = 0U;
    size_t auth_offset = 0U;
    const uint8_t *auth_body = NULL;
    size_t auth_body_len = 0U;
    bool auth_seen = false;

    size_t offset = NTP_HEADER_LEN;

    while (offset < packet_len) {
        if ((packet_len - offset) < 4U) {
            return ESP_ERR_INVALID_SIZE;
        }

        const uint16_t type = read_be16(&packet[offset]);
        const uint16_t field_len = read_be16(&packet[offset + 2U]);

        if (field_len < 4U ||
            (field_len & 0x03U) != 0U ||
            field_len > (packet_len - offset)) {
            return ESP_ERR_INVALID_SIZE;
        }

        const uint8_t *body = &packet[offset + 4U];
        const size_t body_len = (size_t)field_len - 4U;

        if (!auth_seen) {
            switch (type) {
            case NTS_EF_UNIQUE_IDENTIFIER:
                if (uid != NULL ||
                    body_len < 32U ||
                    body_len > NTS_NTP_MAX_UID_LEN) {
                    return ESP_ERR_INVALID_RESPONSE;
                }
                uid = body;
                uid_len = body_len;
                break;

            case NTS_EF_COOKIE:
                if (cookie != NULL ||
                    body_len == 0U ||
                    body_len > NTS_COOKIE_MAX_LEN) {
                    return ESP_ERR_INVALID_RESPONSE;
                }
                cookie = body;
                cookie_len = body_len;
                break;

            case NTS_EF_COOKIE_PLACEHOLDER:
                if (placeholder_count < NTS_NTP_MAX_PLACEHOLDERS) {
                    placeholder_lengths[placeholder_count++] = body_len;
                }
                break;

            case NTS_EF_AUTHENTICATOR:
                auth_seen = true;
                auth_offset = offset;
                auth_body = body;
                auth_body_len = body_len;
                break;

            default:
                break;
            }
        }

        offset += field_len;
    }

    if (uid == NULL || cookie == NULL || !auth_seen || auth_body == NULL) {
        return ESP_ERR_NOT_FOUND;
    }

    if (auth_body_len < 4U) {
        return ESP_ERR_INVALID_SIZE;
    }

    const size_t nonce_len = read_be16(&auth_body[0]);
    const size_t ciphertext_len = read_be16(&auth_body[2]);
    const size_t padded_nonce_len = round_up_4(nonce_len);
    const size_t padded_ciphertext_len = round_up_4(ciphertext_len);

    if (nonce_len != NTS_AES_SIV_NONCE_LEN ||
        ciphertext_len < NTS_AES_SIV_TAG_LEN ||
        4U + padded_nonce_len + padded_ciphertext_len > auth_body_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
     * For AEAD_AES_SIV_CMAC_256, the client nonce is 16 bytes, so the
     * RFC 8915 minimum additional-padding requirement is already satisfied.
     */
    const uint8_t *nonce = &auth_body[4U];
    const uint8_t *ciphertext = &auth_body[4U + padded_nonce_len];

    esp_err_t err = nts_cookie_unpack(cookie, cookie_len, &context->keys);
    if (err != ESP_OK) {
        nts_ntp_auth_clear_context(context);
        return err;
    }

    size_t plaintext_len = sizeof(s_plaintext);

    err = nts_aes_siv_decrypt(
        context->keys.c2s_key,
        packet,
        auth_offset,
        nonce,
        ciphertext,
        ciphertext_len,
        s_plaintext,
        &plaintext_len);

    memset(s_plaintext, 0, sizeof(s_plaintext));

    if (err != ESP_OK) {
        nts_ntp_auth_clear_context(context);
        return err;
    }

    /*
     * 7D.2 supports the mandatory basic request form. Encrypted client
     * extension fields are deliberately deferred; accepting them without
     * parsing their semantics would be unsafe.
     */
    if (plaintext_len != 0U) {
        nts_ntp_auth_clear_context(context);
        return ESP_ERR_NOT_SUPPORTED;
    }

    uint16_t valid_placeholders = 0U;
    for (size_t i = 0U; i < placeholder_count; ++i) {
        if (placeholder_lengths[i] == cookie_len) {
            valid_placeholders++;
        }
    }

    memcpy(context->unique_id, uid, uid_len);
    context->unique_id_len = uid_len;
    context->valid_placeholders = valid_placeholders;
    context->request_length = packet_len;
    context->authenticated = true;

    return ESP_OK;
}

static esp_err_t protect_response_impl(
    const nts_ntp_auth_context_t *context,
    uint8_t *packet,
    size_t base_packet_len,
    size_t packet_capacity,
    size_t *packet_len)
{
    if (context == NULL || packet == NULL || packet_len == NULL ||
        !context->authenticated ||
        base_packet_len != NTP_HEADER_LEN ||
        packet_capacity < base_packet_len ||
        packet_capacity > NTS_NTP_MAX_PACKET_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t offset = base_packet_len;

    esp_err_t err = append_extension(
        packet,
        packet_capacity,
        &offset,
        NTS_EF_UNIQUE_IDENTIFIER,
        context->unique_id,
        context->unique_id_len);
    if (err != ESP_OK) {
        return err;
    }

    uint16_t cookie_count = (uint16_t)(1U + context->valid_placeholders);
    if (cookie_count > (1U + NTS_NTP_MAX_PLACEHOLDERS)) {
        cookie_count = 1U + NTS_NTP_MAX_PLACEHOLDERS;
    }

    memset(s_plaintext, 0, sizeof(s_plaintext));
    size_t plaintext_len = 0U;

    for (uint16_t i = 0U; i < cookie_count; ++i) {
        uint8_t cookie[NTS_COOKIE_MAX_LEN];
        size_t cookie_len = sizeof(cookie);

        err = nts_cookie_create(&context->keys, cookie, &cookie_len);
        if (err != ESP_OK) {
            memset(cookie, 0, sizeof(cookie));
            memset(s_plaintext, 0, sizeof(s_plaintext));
            return err;
        }

        err = append_extension(
            s_plaintext,
            sizeof(s_plaintext),
            &plaintext_len,
            NTS_EF_COOKIE,
            cookie,
            cookie_len);

        memset(cookie, 0, sizeof(cookie));

        if (err != ESP_OK) {
            memset(s_plaintext, 0, sizeof(s_plaintext));
            return err;
        }
    }

    uint8_t nonce[NTS_AES_SIV_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));

    size_t ciphertext_len = sizeof(s_ciphertext);

    err = nts_aes_siv_encrypt(
        context->keys.s2c_key,
        packet,
        offset,
        nonce,
        s_plaintext,
        plaintext_len,
        s_ciphertext,
        &ciphertext_len);

    memset(s_plaintext, 0, sizeof(s_plaintext));

    if (err != ESP_OK) {
        memset(nonce, 0, sizeof(nonce));
        memset(s_ciphertext, 0, sizeof(s_ciphertext));
        return err;
    }

    const size_t padded_nonce_len = round_up_4(sizeof(nonce));
    const size_t padded_ciphertext_len = round_up_4(ciphertext_len);
    const size_t auth_body_len = 4U + padded_nonce_len + padded_ciphertext_len;

    if (auth_body_len > NTS_NTP_MAX_PACKET_SIZE) {
        memset(nonce, 0, sizeof(nonce));
        memset(s_ciphertext, 0, sizeof(s_ciphertext));
        return ESP_ERR_INVALID_SIZE;
    }

    memset(s_auth_body, 0, auth_body_len);

    write_be16(&s_auth_body[0], (uint16_t)sizeof(nonce));
    write_be16(&s_auth_body[2], (uint16_t)ciphertext_len);
    memcpy(&s_auth_body[4U], nonce, sizeof(nonce));
    memcpy(&s_auth_body[4U + padded_nonce_len], s_ciphertext, ciphertext_len);

    err = append_extension(
        packet,
        packet_capacity,
        &offset,
        NTS_EF_AUTHENTICATOR,
        s_auth_body,
        auth_body_len);

    memset(nonce, 0, sizeof(nonce));
    memset(s_ciphertext, 0, sizeof(s_ciphertext));
    memset(s_auth_body, 0, auth_body_len);

    if (err != ESP_OK) {
        return err;
    }

    /* RFC 8915 anti-amplification rule: never exceed the request size. */
    if (offset > context->request_length) {
        return ESP_ERR_INVALID_SIZE;
    }

    *packet_len = offset;
    return ESP_OK;
}

esp_err_t nts_ntp_auth_verify_request(
    const uint8_t *packet,
    size_t packet_len,
    nts_ntp_auth_context_t *context)
{
    stats_increment(&s_stats.verification_attempts);
    const esp_err_t err = verify_request_impl(packet, packet_len, context);
    if (err == ESP_OK) {
        stats_increment(&s_stats.authenticated_requests);
    } else {
        stats_increment(&s_stats.verification_failures);
    }
    return err;
}

esp_err_t nts_ntp_auth_protect_response(
    const nts_ntp_auth_context_t *context,
    uint8_t *packet,
    size_t base_packet_len,
    size_t packet_capacity,
    size_t *packet_len)
{
    const esp_err_t err = protect_response_impl(
        context, packet, base_packet_len, packet_capacity, packet_len);
    if (err == ESP_OK) {
        stats_increment(&s_stats.protected_responses);
    } else {
        stats_increment(&s_stats.protection_failures);
    }
    return err;
}

void nts_ntp_auth_clear_context(nts_ntp_auth_context_t *context)
{
    if (context != NULL) {
        volatile uint8_t *p = (volatile uint8_t *)context;
        for (size_t i = 0U; i < sizeof(*context); ++i) {
            p[i] = 0U;
        }
    }
}
