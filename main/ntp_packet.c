#include "ntp_packet.h"

#include <string.h>

static uint32_t read_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static void write_be32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static ntp_timestamp_t read_timestamp(const uint8_t *data)
{
    const ntp_timestamp_t timestamp = {
        .seconds = read_be32(data),
        .fraction = read_be32(data + 4),
    };

    return timestamp;
}

static void write_timestamp(uint8_t *data, ntp_timestamp_t timestamp)
{
    write_be32(data, timestamp.seconds);
    write_be32(data + 4, timestamp.fraction);
}

bool ntp_packet_parse(const uint8_t *buffer,
                      size_t length,
                      ntp_packet_fields_t *out_packet)
{
    if (buffer == NULL ||
        out_packet == NULL ||
        length < NTP_PACKET_SIZE) {
        return false;
    }

    const uint8_t first_octet = buffer[0];

    memset(out_packet, 0, sizeof(*out_packet));

    out_packet->leap_indicator = (first_octet >> 6) & 0x03U;
    out_packet->version = (first_octet >> 3) & 0x07U;
    out_packet->mode = first_octet & 0x07U;

    out_packet->stratum = buffer[1];
    out_packet->precision = (int8_t)buffer[3];

    out_packet->root_delay = read_be32(&buffer[4]);
    out_packet->root_dispersion = read_be32(&buffer[8]);
    out_packet->reference_id = read_be32(&buffer[12]);

    out_packet->reference_timestamp = read_timestamp(&buffer[16]);
    out_packet->origin_timestamp = read_timestamp(&buffer[24]);
    out_packet->receive_timestamp = read_timestamp(&buffer[32]);
    out_packet->transmit_timestamp = read_timestamp(&buffer[40]);

    return true;
}

void ntp_packet_build(uint8_t out_buffer[NTP_PACKET_SIZE],
                      const ntp_packet_fields_t *packet)
{
    if (out_buffer == NULL || packet == NULL) {
        return;
    }

    memset(out_buffer, 0, NTP_PACKET_SIZE);

    out_buffer[0] =
        (uint8_t)(((packet->leap_indicator & 0x03U) << 6) |
                  ((packet->version & 0x07U) << 3) |
                  (packet->mode & 0x07U));

    out_buffer[1] = packet->stratum;
    out_buffer[2] = 6U;
    out_buffer[3] = (uint8_t)packet->precision;

    write_be32(&out_buffer[4], packet->root_delay);
    write_be32(&out_buffer[8], packet->root_dispersion);
    write_be32(&out_buffer[12], packet->reference_id);

    write_timestamp(&out_buffer[16], packet->reference_timestamp);
    write_timestamp(&out_buffer[24], packet->origin_timestamp);
    write_timestamp(&out_buffer[32], packet->receive_timestamp);
    write_timestamp(&out_buffer[40], packet->transmit_timestamp);
}

uint32_t ntp_packet_refid_from_text(const char text[4])
{
    if (text == NULL) {
        return 0U;
    }

    return ((uint32_t)(uint8_t)text[0] << 24) |
           ((uint32_t)(uint8_t)text[1] << 16) |
           ((uint32_t)(uint8_t)text[2] << 8) |
           (uint32_t)(uint8_t)text[3];
}