#include "nts_packet.h"

#include <string.h>

#include "app_config.h"
#include "app_state.h"
#include "ntp_packet.h"
#include "ntp_types.h"
#include "nts_aes_siv.h"
#include "nts_cookie.h"

#include "esp_random.h"

typedef struct {
    const uint8_t *unique_id;
    size_t unique_id_len;

    const uint8_t *cookie;
    size_t cookie_len;

    const uint8_t *auth_field;
    size_t auth_field_len;
    size_t auth_field_offset;

    uint16_t cookie_placeholders;
} nts_request_fields_t;

static uint16_t read_u16_be(const uint8_t *source)
{
    return (uint16_t)(
        ((uint16_t)source[0] << 8) |
        source[1]);
}

static void write_u16_be(uint8_t *destination,
                         uint16_t value)
{
    destination[0] = (uint8_t)(value >> 8);
    destination[1] = (uint8_t)value;
}

static bool append_extension_field(
    uint8_t *buffer,
    size_t capacity,
    size_t *offset,
    uint16_t type,
    const uint8_t *value,
    size_t value_len)
{
    if (buffer == NULL ||
        offset == NULL ||
        value == NULL) {
        return false;
    }

    size_t total_len = 4U + value_len;

    if (total_len < 16U ||
        (total_len & 0x03U) != 0U ||
        total_len > UINT16_MAX ||
        (*offset + total_len) > capacity) {
        return false;
    }

    write_u16_be(&buffer[*offset], type);
    write_u16_be(&buffer[*offset + 2U],
                 (uint16_t)total_len);

    memcpy(&buffer[*offset + 4U],
           value,
           value_len);

    *offset += total_len;

    return true;
}

static bool parse_authenticator_field(
    const uint8_t *field_value,
    size_t field_value_len,
    const uint8_t **nonce,
    size_t *nonce_len,
    const uint8_t **ciphertext,
    size_t *ciphertext_len)
{
    if (field_value == NULL ||
        nonce == NULL ||
        nonce_len == NULL ||
        ciphertext == NULL ||
        ciphertext_len == NULL ||
        field_value_len < 4U) {
        return false;
    }

    uint16_t parsed_nonce_len =
        read_u16_be(&field_value[0]);

    uint16_t parsed_ciphertext_len =
        read_u16_be(&field_value[2]);

    size_t required_len =
        4U +
        (size_t)parsed_nonce_len +
        (size_t)parsed_ciphertext_len;

    if (parsed_nonce_len != NTS_AES_SIV_NONCE_LEN ||
        parsed_ciphertext_len < NTS_AES_SIV_TAG_LEN ||
        required_len > field_value_len) {
        return false;
    }

    *nonce = &field_value[4U];
    *nonce_len = parsed_nonce_len;

    *ciphertext =
        &field_value[4U + parsed_nonce_len];

    *ciphertext_len = parsed_ciphertext_len;

    return true;
}

static esp_err_t parse_nts_request(
    const uint8_t *request,
    size_t request_len,
    nts_request_fields_t *fields)
{
    if (request == NULL ||
        fields == NULL ||
        request_len < NTP_HEADER_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(fields, 0, sizeof(*fields));

    size_t offset = NTP_HEADER_LEN;

    while (offset < request_len) {
        if ((request_len - offset) < 4U) {
            return ESP_ERR_INVALID_SIZE;
        }

        uint16_t type =
            read_u16_be(&request[offset]);

        uint16_t field_len =
            read_u16_be(&request[offset + 2U]);

        if (field_len < 16U ||
            (field_len & 0x03U) != 0U ||
            field_len > (request_len - offset)) {
            return ESP_ERR_INVALID_SIZE;
        }

        const uint8_t *value =
            &request[offset + 4U];

        size_t value_len =
            field_len - 4U;

        switch (type) {
        case NTS_EF_UNIQUE_IDENTIFIER:
            if (fields->unique_id != NULL ||
                value_len == 0U ||
                value_len > NTS_MAX_UID_LEN) {
                return ESP_ERR_INVALID_RESPONSE;
            }

            fields->unique_id = value;
            fields->unique_id_len = value_len;
            break;

        case NTS_EF_COOKIE:
            if (fields->cookie == NULL) {
                if (value_len == 0U ||
                    value_len > NTS_MAX_COOKIE_LEN) {
                    return ESP_ERR_INVALID_SIZE;
                }

                fields->cookie = value;
                fields->cookie_len = value_len;
            }
            break;

        case NTS_EF_COOKIE_PLACEHOLDER:
            if (value_len != 0U) {
                return ESP_ERR_INVALID_RESPONSE;
            }

            if (fields->cookie_placeholders <
                APP_NTS_MAX_COOKIE_COUNT) {
                fields->cookie_placeholders++;
            }
            break;

        case NTS_EF_AUTHENTICATOR:
            /*
             * Authenticator must be the final extension field.
             */
            if (fields->auth_field != NULL ||
                (offset + field_len) != request_len) {
                return ESP_ERR_INVALID_RESPONSE;
            }

            fields->auth_field = value;
            fields->auth_field_len = value_len;
            fields->auth_field_offset = offset;
            break;

        default:
            /*
             * Unknown extension fields are allowed only before the
             * final authenticator. They are included in AEAD
             * associated data.
             */
            break;
        }

        offset += field_len;
    }

    if (fields->unique_id == NULL ||
        fields->cookie == NULL ||
        fields->auth_field == NULL) {
        return ESP_ERR_NOT_FOUND;
    }

    return ESP_OK;
}

static void build_ntsn_kod(
    const ntp_header_t *request,
    uint8_t *response,
    size_t *response_len)
{
    ntp_timestamp_t now;
    ntp_header_t kod;

    app_state_get_ntp_timestamp(&now);

    ntp_packet_make_kod(
        &kod,
        request,
        NTP_KOD_NTSN,
        &now);

    if (ntp_packet_serialize(
            &kod,
            response,
            NTP_HEADER_LEN) == NTP_PACKET_OK) {
        *response_len = NTP_HEADER_LEN;
    } else {
        *response_len = 0U;
    }
}

static void build_nts_response_header(
    const ntp_header_t *request,
    ntp_header_t *response)
{
    uint8_t stratum = NTP_STRATUM_UNSYNCED;
    uint8_t leap = NTP_LI_UNSYNCED;

    uint32_t root_delay = 0U;
    uint32_t root_dispersion = 0U;

    ntp_timestamp_t t2;
    ntp_timestamp_t t3;

    app_state_get_ntp_status(
        &stratum,
        &leap,
        &root_delay,
        &root_dispersion);

    app_state_get_ntp_timestamp(&t2);
    app_state_get_ntp_timestamp(&t3);

    memset(response, 0, sizeof(*response));

    response->li_vn_mode = ntp_make_lvm(
        leap,
        ntp_get_version(request->li_vn_mode),
        NTP_MODE_SERVER);

    response->stratum = stratum;
    response->poll = request->poll;
    response->precision = -10;

    response->root_delay = root_delay;
    response->root_dispersion = root_dispersion;

    if (stratum == NTP_STRATUM_UNSYNCED) {
        memcpy(response->ref_id, "INIT", 4U);
    } else if (stratum == 1U) {
        memcpy(response->ref_id, "GPS\0", 4U);
    } else {
        memcpy(response->ref_id, "HOLD", 4U);
    }

    response->reference_ts = t2;
    response->origin_ts = request->transmit_ts;
    response->receive_ts = t2;
    response->transmit_ts = t3;
}

static bool append_nts_authenticator(
    uint8_t *response,
    size_t response_capacity,
    size_t *response_offset,
    const uint8_t s2c_key[NTS_TRAFFIC_KEY_LEN])
{
    if (response == NULL ||
        response_offset == NULL ||
        s2c_key == NULL) {
        return false;
    }

    uint8_t nonce[NTS_AES_SIV_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));

    uint8_t encrypted[NTS_AES_SIV_TAG_LEN];
    size_t encrypted_len = sizeof(encrypted);

    esp_err_t err = nts_aes_siv_encrypt(
        s2c_key,
        response,
        *response_offset,
        nonce,
        NULL,
        0U,
        encrypted,
        &encrypted_len);

    if (err != ESP_OK ||
        encrypted_len != NTS_AES_SIV_TAG_LEN) {
        return false;
    }

    uint8_t auth_value[
        4U +
        NTS_AES_SIV_NONCE_LEN +
        NTS_AES_SIV_TAG_LEN];

    write_u16_be(
        &auth_value[0],
        NTS_AES_SIV_NONCE_LEN);

    write_u16_be(
        &auth_value[2],
        (uint16_t)encrypted_len);

    memcpy(&auth_value[4],
           nonce,
           sizeof(nonce));

    memcpy(&auth_value[
               4U + NTS_AES_SIV_NONCE_LEN],
           encrypted,
           encrypted_len);

    bool result = append_extension_field(
        response,
        response_capacity,
        response_offset,
        NTS_EF_AUTHENTICATOR,
        auth_value,
        sizeof(auth_value));

    memset(nonce, 0, sizeof(nonce));
    memset(encrypted, 0, sizeof(encrypted));
    memset(auth_value, 0, sizeof(auth_value));

    return result;
}

esp_err_t nts_packet_process(
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    if (request == NULL ||
        response == NULL ||
        response_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *response_len = 0U;

    if (request_len > APP_NTS_MAX_PACKET_SIZE ||
        response_capacity > APP_NTS_MAX_PACKET_SIZE) {
        return ESP_ERR_INVALID_SIZE;
    }

    ntp_header_t request_header;

    ntp_packet_result_t parse_result =
        ntp_packet_parse(
            request,
            request_len,
            &request_header);

    if (parse_result != NTP_PACKET_OK ||
        ntp_get_mode(request_header.li_vn_mode) !=
            NTP_MODE_CLIENT) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    nts_request_fields_t fields;

    esp_err_t err = parse_nts_request(
        request,
        request_len,
        &fields);

    if (err != ESP_OK) {
        build_ntsn_kod(
            &request_header,
            response,
            response_len);

        return err;
    }

    const uint8_t *nonce = NULL;
    const uint8_t *ciphertext = NULL;

    size_t nonce_len = 0U;
    size_t ciphertext_len = 0U;

    if (!parse_authenticator_field(
            fields.auth_field,
            fields.auth_field_len,
            &nonce,
            &nonce_len,
            &ciphertext,
            &ciphertext_len)) {
        build_ntsn_kod(
            &request_header,
            response,
            response_len);

        return ESP_ERR_INVALID_RESPONSE;
    }

    nts_cookie_keys_t request_keys;

    err = nts_cookie_unpack(
        fields.cookie,
        fields.cookie_len,
        &request_keys);

    if (err != ESP_OK) {
        build_ntsn_kod(
            &request_header,
            response,
            response_len);

        return err;
    }

    uint8_t decrypted[
        APP_NTS_MAX_PACKET_SIZE];

    size_t decrypted_len =
        sizeof(decrypted);

    /*
     * Associated data is all NTP packet bytes before the
     * NTS Authenticator and Encrypted Extension Fields extension.
     */
    err = nts_aes_siv_decrypt(
        request_keys.c2s_key,
        request,
        fields.auth_field_offset,
        nonce,
        ciphertext,
        ciphertext_len,
        decrypted,
        &decrypted_len);

    memset(request_keys.c2s_key,
           0,
           sizeof(request_keys.c2s_key));

    if (err != ESP_OK) {
        memset(decrypted, 0, sizeof(decrypted));

        build_ntsn_kod(
            &request_header,
            response,
            response_len);

        return err;
    }

    /*
     * This implementation does not yet support encrypted NTP
     * extension fields. A valid basic NTS client request therefore
     * must decrypt to an empty plaintext.
     */
    if (decrypted_len != 0U) {
        memset(decrypted, 0, sizeof(decrypted));
        memset(request_keys.s2c_key,
               0,
               sizeof(request_keys.s2c_key));

        build_ntsn_kod(
            &request_header,
            response,
            response_len);

        return ESP_ERR_NOT_SUPPORTED;
    }

    memset(decrypted, 0, sizeof(decrypted));

    ntp_header_t response_header;

    build_nts_response_header(
        &request_header,
        &response_header);

    if (response_capacity < NTP_HEADER_LEN ||
        ntp_packet_serialize(
            &response_header,
            response,
            response_capacity) != NTP_PACKET_OK) {
        memset(request_keys.s2c_key,
               0,
               sizeof(request_keys.s2c_key));

        return ESP_ERR_INVALID_SIZE;
    }

    size_t response_offset = NTP_HEADER_LEN;

    if (!append_extension_field(
            response,
            response_capacity,
            &response_offset,
            NTS_EF_UNIQUE_IDENTIFIER,
            fields.unique_id,
            fields.unique_id_len)) {
        memset(request_keys.s2c_key,
               0,
               sizeof(request_keys.s2c_key));

        return ESP_ERR_INVALID_SIZE;
    }

    uint16_t requested_cookies =
        fields.cookie_placeholders;

    if (requested_cookies == 0U) {
        requested_cookies = 1U;
    }

    if (requested_cookies >
        APP_NTS_MAX_COOKIE_COUNT) {
        requested_cookies =
            APP_NTS_MAX_COOKIE_COUNT;
    }

    for (uint16_t i = 0U;
         i < requested_cookies;
         i++) {
        nts_cookie_keys_t new_cookie_keys;

        err = nts_cookie_generate_keys(
            &new_cookie_keys,
            APP_NTS_COOKIE_LIFETIME_SECONDS);

        if (err != ESP_OK) {
            break;
        }

        uint8_t cookie[NTS_COOKIE_MAX_LEN];
        size_t cookie_len = sizeof(cookie);

        err = nts_cookie_create(
            &new_cookie_keys,
            cookie,
            &cookie_len);

        memset(&new_cookie_keys,
               0,
               sizeof(new_cookie_keys));

        if (err != ESP_OK) {
            memset(cookie, 0, sizeof(cookie));
            break;
        }

        bool appended = append_extension_field(
            response,
            response_capacity,
            &response_offset,
            NTS_EF_COOKIE,
            cookie,
            cookie_len);

        memset(cookie, 0, sizeof(cookie));

        if (!appended) {
            memset(request_keys.s2c_key,
                   0,
                   sizeof(request_keys.s2c_key));

            return ESP_ERR_INVALID_SIZE;
        }
    }

    bool auth_ok = append_nts_authenticator(
        response,
        response_capacity,
        &response_offset,
        request_keys.s2c_key);

    memset(request_keys.s2c_key,
           0,
           sizeof(request_keys.s2c_key));

    if (!auth_ok) {
        return ESP_FAIL;
    }

    *response_len = response_offset;

    return ESP_OK;
}