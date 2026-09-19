#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool running;
    uint32_t tls_handshake_failures;
    uint32_t alpn_rejections;
    uint32_t exchanges_completed;
    uint32_t exchange_failures;
} nts_ke_stats_t;

esp_err_t nts_ke_start(void);
bool nts_ke_is_running(void);
void nts_ke_get_stats(nts_ke_stats_t *stats);

#ifdef __cplusplus
}
#endif
