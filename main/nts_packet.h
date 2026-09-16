#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#define NTS_EF_UNIQUE_IDENTIFIER       0x0104U
#define NTS_EF_COOKIE                  0x0204U
#define NTS_EF_COOKIE_PLACEHOLDER      0x0304U
#define NTS_EF_AUTHENTICATOR            0x0404U

#define NTS_MAX_UID_LEN                 256U
#define NTS_MAX_COOKIE_LEN              256U
#define NTS_MAX_COOKIES_PER_RESPONSE    4U

esp_err_t nts_packet_process(
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len);
