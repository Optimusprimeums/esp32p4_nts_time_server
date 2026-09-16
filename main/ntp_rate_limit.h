#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void ntp_rate_limit_init(void);

/*
 * Returns true when a request may be serviced.
 *
 * out_send_kod is true when the request must receive a RATE KoD packet.
 */
bool ntp_rate_limit_allow(uint32_t client_ipv4,
                          bool *out_send_kod);

#ifdef __cplusplus
}
#endif