#pragma once

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t web_console_start(void);

bool web_console_is_running(void);

#ifdef __cplusplus
}
#endif
