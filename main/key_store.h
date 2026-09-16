#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#define KEY_STORE_COOKIE_KEY_LEN       32U
#define KEY_STORE_COOKIE_KEY_SLOTS     3U

#define KEY_STORE_SLOT_PREVIOUS        0U
#define KEY_STORE_SLOT_ACTIVE          1U
#define KEY_STORE_SLOT_NEXT            2U

typedef struct {
    uint32_t key_id;

    uint64_t not_before_ntp;
    uint64_t not_after_ntp;

    uint8_t key[KEY_STORE_COOKIE_KEY_LEN];

    uint8_t valid;
} key_store_cookie_key_t;

typedef struct {
    key_store_cookie_key_t slots[
        KEY_STORE_COOKIE_KEY_SLOTS];
} key_store_cookie_keyring_t;

esp_err_t key_store_init(void);

esp_err_t key_store_load_blob(
    const char *name,
    void *buffer,
    size_t *buffer_len);

esp_err_t key_store_save_blob(
    const char *name,
    const void *buffer,
    size_t buffer_len);

esp_err_t key_store_erase_blob(
    const char *name);

esp_err_t key_store_load_cookie_keyring(
    key_store_cookie_keyring_t *keyring);

esp_err_t key_store_save_cookie_keyring(
    const key_store_cookie_keyring_t *keyring);

esp_err_t key_store_load_tls_certificate(
    uint8_t *buffer,
    size_t *buffer_len);

esp_err_t key_store_load_tls_private_key(
    uint8_t *buffer,
    size_t *buffer_len);

esp_err_t key_store_load_gateway_public_key(
    uint8_t *buffer,
    size_t *buffer_len);

esp_err_t key_store_save_tls_certificate(
    const uint8_t *buffer,
    size_t buffer_len);

esp_err_t key_store_save_tls_private_key(
    const uint8_t *buffer,
    size_t buffer_len);

esp_err_t key_store_ensure_cookie_keyring(void);

void key_store_zeroize(
    void *buffer,
    size_t length);
