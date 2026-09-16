#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NTP_PACKET_SIZE                         48U
#define NTP_PORT                                123U

#define NTP_LI_NO_WARNING                       0U
#define NTP_LI_ADD_SECOND                       1U
#define NTP_LI_DELETE_SECOND                    2U
#define NTP_LI_UNSYNCED                         3U

#define NTP_VERSION_3                           3U
#define NTP_VERSION_4                           4U

#define NTP_MODE_RESERVED                       0U
#define NTP_MODE_SYMMETRIC_ACTIVE               1U
#define NTP_MODE_SYMMETRIC_PASSIVE              2U
#define NTP_MODE_CLIENT                         3U
#define NTP_MODE_SERVER                         4U
#define NTP_MODE_BROADCAST                      5U

#define NTP_STRATUM_KOD                         0U
#define NTP_STRATUM_PRIMARY                     1U
#define NTP_STRATUM_SECONDARY                   2U
#define NTP_STRATUM_UNSYNCED                    16U

typedef struct {
    uint32_t seconds;
    uint32_t fraction;
} ntp_timestamp_t;

typedef struct {
    uint8_t leap_indicator;
    uint8_t version;
    uint8_t mode;
    uint8_t stratum;
    int8_t precision;

    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_id;

    ntp_timestamp_t reference_timestamp;
    ntp_timestamp_t origin_timestamp;
    ntp_timestamp_t receive_timestamp;
    ntp_timestamp_t transmit_timestamp;
} ntp_packet_fields_t;