#include "nts_cookie.h"

#include <string.h>

#include "app_state.h"
#include "key_store.h"
#include "nts_aes_siv.h"

#include "esp_random.h"

#define NTS_COOKIE_MAGIC           0x4E545343UL
#define NTS_COOKIE_VERSION         1U

#define NTS_COOKIE_PLAINTEXT_LEN   \
    (4U + 2U + 2U + 4U + 8U + 8U + \
     NTS_TRAFFIC_KEY_LEN +         \
     NTS_TRAFFIC_KEY_LEN)

#define NTS_COOKIE_WIRE_PREFIX_LEN \
    (4U + NTS_COOKIE_NONCE_LEN)

static void write_u16_be(
    uint8_t *destination,
    uint16_t value)
{
    destination[0] = (uint8_t)(value >> 8);
    destination[1] = (uint8_t)value;
}

static void write_u32_be(
    uint8_t *destination,
    uint32_t value)
{
    destination[0] = (uint8_t)(value >> 24);
    destination[1] = (uint8_t)(value >> 16);
    destination[2] = (uint8_t)(value >> 8);
    destination[3] = (uint8_t)value;
}

static void write_u64_be(
    uint8_t *destination,
    uint64_t value)
{
    for (int i = 7; i >= 0; i--) {
        destination[7 - i] =
            (uint8_t)(value >> (i * 8));
    }
}

static uint16_t read_u16_be(
    const uint8_t *source)
{
    return (uint16_t)(
        ((uint16_t)source[0] << 8) |
        source[1]);
}

static uint32_t read_u32_be(
    const uint8_t *source)
{
    return ((uint32_t)source[0] << 24) |
           ((uint32_t)source[1] << 16) |
           ((uint32_t)source[2] << 8) |
           ((uint32_t)source[3]);
}

static uint64_t read_u64_be(
    const uint8_t *source)
{
    uint64_t value = 0U;

    for (size_t i = 0; i < 8U; i++) {
        value = (value << 8) | source[i];
    }

    return value;
}

static uint64_t current_ntp_seconds(void)
{
    ntp_timestamp_t timestamp;

    app_state_get_ntp_timestamp(&timestamp);

    return timestamp.seconds;
}

static const key_store_cookie_key_t *
find_cookie_master_key(
    const key_store_cookie_keyring_t *keyring,
    uint32_t key_id)
{
    for (size_t i = 0;
         i < KEY_STORE_COOKIE_KEY_SLOTS;
         i++) {
        const key_store_cookie_key_t *key =
            &keyring->slots[i];

        if (key->valid != 0U &&
            key->key_id == key_id) {
            return key;
        }
    }

    return NULL;
}

static const key_store_cookie_key_t *
get_active_cookie_master_key(
    const key_store_cookie_keyring_t *keyring)
{
    const key_store_cookie_key_t *active =
        &keyring->slots[
            KEY_STORE_SLOT_ACTIVE];

    if (active->valid == 0U) {
        return NULL;
    }

    return active;
}

esp_err_t nts_cookie_generate_keys(
    nts_cookie_keys_t *keys,
    uint64_t lifetime_seconds)
{
    if (keys == NULL ||
        lifetime_seconds == 0U) {
        return ESP_ERR_INVALID_ARG;
    }

    key_store_cookie_keyring_t keyring;

    esp_err_t err =
        key_store_load_cookie_keyring(
            &keyring);

    if (err != ESP_OK) {
        return err;
    }

    const key_store_cookie_key_t *active =
        get_active_cookie_master_key(
            &keyring);

    if (active == NULL) {
        key_store_zeroize(
            &keyring,
            sizeof(keyring));

        return ESP_ERR_NOT_FOUND;
    }

    uint64_t now_ntp =
        current_ntp_seconds();

    memset(keys, 0, sizeof(*keys));

    esp_fill_random(
        keys->c2s_key,
        sizeof(keys->c2s_key));

    esp_fill_random(
        keys->s2c_key,
        sizeof(keys->s2c_key));

    keys->master_key_id =
        active->key_id;

    keys->issued_ntp_seconds =
        now_ntp;

    keys->expires_ntp_seconds =
        now_ntp + lifetime_seconds;

    key_store_zeroize(
        &keyring,
        sizeof(keyring));

    return ESP_OK;
}

esp_err_t nts_cookie_create(
    const nts_cookie_keys_t *keys,
    uint8_t *cookie,
    size_t *cookie_len)
{
    if (keys == NULL ||
        cookie == NULL ||
        cookie_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    key_store_cookie_keyring_t keyring;

    esp_err_t err =
        key_store_load_cookie_keyring(
            &keyring);

    if (err != ESP_OK) {
        return err;
    }

    const key_store_cookie_key_t *master =
        get_active_cookie_master_key(
            &keyring);

    if (master == NULL) {
        key_store_zeroize(
            &keyring,
            sizeof(keyring));

        return ESP_ERR_NOT_FOUND;
    }

    size_t encrypted_len =
        NTS_AES_SIV_TAG_LEN +
        NTS_COOKIE_PLAINTEXT_LEN;

    size_t required_len =
        NTS_COOKIE_WIRE_PREFIX_LEN +
        encrypted_len;

    if (*cookie_len < required_len) {
        *cookie_len = required_len;

        key_store_zeroize(
            &keyring,
            sizeof(keyring));

        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t plaintext[
        NTS_COOKIE_PLAINTEXT_LEN];

    memset(plaintext, 0, sizeof(plaintext));

    size_t offset = 0U;

    write_u32_be(
        &plaintext[offset],
        NTS_COOKIE_MAGIC);
    offset += 4U;

    write_u16_be(
        &plaintext[offset],
        NTS_COOKIE_VERSION);
    offset += 2U;

    write_u16_be(
        &plaintext[offset],
        0U);
    offset += 2U;

    write_u32_be(
        &plaintext[offset],
        master->key_id);
    offset += 4U;

    write_u64_be(
        &plaintext[offset],
        keys->issued_ntp_seconds);
    offset += 8U;

    write_u64_be(
        &plaintext[offset],
        keys->expires_ntp_seconds);
    offset += 8U;

    memcpy(&plaintext[offset],
           keys->c2s_key,
           NTS_TRAFFIC_KEY_LEN);
    offset += NTS_TRAFFIC_KEY_LEN;

    memcpy(&plaintext[offset],
           keys->s2c_key,
           NTS_TRAFFIC_KEY_LEN);
    offset += NTS_TRAFFIC_KEY_LEN;

    if (offset != sizeof(plaintext)) {
        key_store_zeroize(
            plaintext,
            sizeof(plaintext));

        key_store_zeroize(
            &keyring,
            sizeof(keyring));

        return ESP_FAIL;
    }

    write_u32_be(
        &cookie[0],
        master->key_id);

    uint8_t *nonce = &cookie[4];

    esp_fill_random(
        nonce,
        NTS_COOKIE_NONCE_LEN);

    size_t output_len = encrypted_len;

    err = nts_aes_siv_encrypt(
        master->key,
        cookie,
        4U,
        nonce,
        plaintext,
        sizeof(plaintext),
        &cookie[NTS_COOKIE_WIRE_PREFIX_LEN],
        &output_len);

    key_store_zeroize(
        plaintext,
        sizeof(plaintext));

    key_store_zeroize(
        &keyring,
        sizeof(keyring));

    if (err != ESP_OK) {
        key_store_zeroize(
            cookie,
            required_len);

        return err;
    }

    *cookie_len =
        NTS_COOKIE_WIRE_PREFIX_LEN +
        output_len;

    return ESP_OK;
}

esp_err_t nts_cookie_unpack(
    const uint8_t *cookie,
    size_t cookie_len,
    nts_cookie_keys_t *keys)
{
    if (cookie == NULL ||
        keys == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t expected_len =
        NTS_COOKIE_WIRE_PREFIX_LEN +
        NTS_AES_SIV_TAG_LEN +
        NTS_COOKIE_PLAINTEXT_LEN;

    if (cookie_len != expected_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint32_t master_key_id =
        read_u32_be(&cookie[0]);

    const uint8_t *nonce =
        &cookie[4];

    const uint8_t *encrypted =
        &cookie[NTS_COOKIE_WIRE_PREFIX_LEN];

    size_t encrypted_len =
        cookie_len -
        NTS_COOKIE_WIRE_PREFIX_LEN;

    key_store_cookie_keyring_t keyring;

    esp_err_t err =
        key_store_load_cookie_keyring(
            &keyring);

    if (err != ESP_OK) {
        return err;
    }

    const key_store_cookie_key_t *master =
        find_cookie_master_key(
            &keyring,
            master_key_id);

    if (master == NULL) {
        key_store_zeroize(
            &keyring,
            sizeof(keyring));

        return ESP_ERR_NOT_FOUND;
    }

    uint8_t plaintext[
        NTS_COOKIE_PLAINTEXT_LEN];

    size_t plaintext_len =
        sizeof(plaintext);

    err = nts_aes_siv_decrypt(
        master->key,
        cookie,
        4U,
        nonce,
        encrypted,
        encrypted_len,
        plaintext,
        &plaintext_len);

    key_store_zeroize(
        &keyring,
        sizeof(keyring));

    if (err != ESP_OK) {
        key_store_zeroize(
            plaintext,
            sizeof(plaintext));

        return err;
    }

    if (plaintext_len !=
        NTS_COOKIE_PLAINTEXT_LEN) {
        key_store_zeroize(
            plaintext,
            sizeof(plaintext));

        return ESP_ERR_INVALID_SIZE;
    }

    size_t offset = 0U;

    uint32_t magic =
        read_u32_be(&plaintext[offset]);
    offset += 4U;

    uint16_t version =
        read_u16_be(&plaintext[offset]);
    offset += 2U;

    uint16_t reserved =
        read_u16_be(&plaintext[offset]);
    offset += 2U;

    uint32_t payload_master_key_id =
        read_u32_be(&plaintext[offset]);
    offset += 4U;

    uint64_t issued_ntp_seconds =
        read_u64_be(&plaintext[offset]);
    offset += 8U;

    uint64_t expires_ntp_seconds =
        read_u64_be(&plaintext[offset]);
    offset += 8U;

    if (magic != NTS_COOKIE_MAGIC ||
        version != NTS_COOKIE_VERSION ||
        reserved != 0U ||
        payload_master_key_id !=
            master_key_id) {
        key_store_zeroize(
            plaintext,
            sizeof(plaintext));

        return ESP_ERR_INVALID_RESPONSE;
    }

    uint64_t now_ntp =
        current_ntp_seconds();

    if (expires_ntp_seconds <= now_ntp ||
        issued_ntp_seconds > now_ntp) {
        key_store_zeroize(
            plaintext,
            sizeof(plaintext));

        return ESP_ERR_INVALID_STATE;
    }

    memset(keys, 0, sizeof(*keys));

    keys->master_key_id =
        master_key_id;

    keys->issued_ntp_seconds =
        issued_ntp_seconds;

    keys->expires_ntp_seconds =
        expires_ntp_seconds;

    memcpy(keys->c2s_key,
           &plaintext[offset],
           NTS_TRAFFIC_KEY_LEN);
    offset += NTS_TRAFFIC_KEY_LEN;

    memcpy(keys->s2c_key,
           &plaintext[offset],
           NTS_TRAFFIC_KEY_LEN);
    offset += NTS_TRAFFIC_KEY_LEN;

    key_store_zeroize(
        plaintext,
        sizeof(plaintext));

    if (offset !=
        NTS_COOKIE_PLAINTEXT_LEN) {
        key_store_zeroize(
            keys,
            sizeof(*keys));

        return ESP_FAIL;
    }

    return ESP_OK;
}