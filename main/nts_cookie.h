#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#define NTS_TRAFFIC_KEY_LEN        32U
#define NTS_COOKIE_NONCE_LEN       16U
#define NTS_COOKIE_MAX_LEN         256U

typedef struct {
    uint8_t c2s_key[NTS_TRAFFIC_KEY_LEN];
    uint8_t s2c_key[NTS_TRAFFIC_KEY_LEN];

    uint32_t master_key_id;

    uint64_t issued_ntp_seconds;
    uint64_t expires_ntp_seconds;
} nts_cookie_keys_t;

esp_err_t nts_cookie_generate_keys(
    nts_cookie_keys_t *keys,
    uint64_t lifetime_seconds);

esp_err_t nts_cookie_create(
    const nts_cookie_keys_t *keys,
    uint8_t *cookie,
    size_t *cookie_len);

esp_err_t nts_cookie_unpack(
    const uint8_t *cookie,
    size_t cookie_len,
    nts_cookie_keys_t *keys);