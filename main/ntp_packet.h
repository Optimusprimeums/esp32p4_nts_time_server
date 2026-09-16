#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ntp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

bool ntp_packet_parse(const uint8_t *buffer,
                      size_t length,
                      ntp_packet_fields_t *out_packet);

void ntp_packet_build(uint8_t out_buffer[NTP_PACKET_SIZE],
                      const ntp_packet_fields_t *packet);

uint32_t ntp_packet_refid_from_text(const char text[4]);

#ifdef __cplusplus
}
#endif