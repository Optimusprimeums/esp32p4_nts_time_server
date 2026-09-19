#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t hp_lp_test_start(void);

esp_err_t hp_lp_test_start_pps_comparison(void);

#ifdef __cplusplus
}
#endif