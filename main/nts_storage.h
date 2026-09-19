#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#define NTS_STORAGE_COOKIE_KEY_LEN       32U
#define NTS_STORAGE_COOKIE_KEY_SLOTS     3U

#define NTS_STORAGE_SLOT_PREVIOUS        0U
#define NTS_STORAGE_SLOT_ACTIVE          1U
#define NTS_STORAGE_SLOT_NEXT            2U

typedef struct {
    uint32_t key_id;

    uint64_t not_before_ntp;
    uint64_t not_after_ntp;

    uint8_t key[NTS_STORAGE_COOKIE_KEY_LEN];

    uint8_t valid;
} nts_storage_cookie_key_t;

typedef struct {
    nts_storage_cookie_key_t slots[
        NTS_STORAGE_COOKIE_KEY_SLOTS];
} nts_storage_cookie_keyring_t;

esp_err_t nts_storage_init(void);

esp_err_t nts_storage_load_cookie_keyring(
    nts_storage_cookie_keyring_t *keyring);

esp_err_t nts_storage_save_cookie_keyring(
    const nts_storage_cookie_keyring_t *keyring);

esp_err_t nts_storage_ensure_cookie_keyring(void);

esp_err_t nts_storage_maintain_cookie_keyring(void);

void nts_storage_zeroize(
    void *buffer,
    size_t length);
