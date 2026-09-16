#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    bool certificate_present;
    bool private_key_present;
    bool cookie_ring_present;

    size_t certificate_length;
    size_t private_key_length;
} nts_provisioning_status_t;

esp_err_t nts_provisioning_store_certificate(
    const uint8_t *certificate_pem,
    size_t certificate_pem_len);

esp_err_t nts_provisioning_store_private_key(
    const uint8_t *private_key_pem,
    size_t private_key_pem_len);

esp_err_t nts_provisioning_ensure_cookie_ring(void);

esp_err_t nts_provisioning_finalize(void);

esp_err_t nts_provisioning_get_status(
    nts_provisioning_status_t *status);