#include "gnss_service.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app_config.h"

#include "driver/uart.h"

#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/task.h"

static const char *TAG = "GNSS";

#define GNSS_LINE_MAX_LENGTH                    160U
#define GNSS_READ_BUFFER_SIZE                   256U

#define UBX_SYNC_1                              0xB5U
#define UBX_SYNC_2                              0x62U

#define UBX_CLASS_NAV                           0x01U
#define UBX_CLASS_MON                           0x0AU
#define UBX_CLASS_ACK                           0x05U
#define UBX_CLASS_CFG                           0x06U
#define UBX_CLASS_TIM                           0x0DU
#define UBX_CLASS_NMEA                          0xF0U

#define UBX_ID_ACK_NAK                          0x00U
#define UBX_ID_ACK_ACK                          0x01U

#define UBX_ID_NAV_PVT                          0x07U
#define UBX_ID_NAV_TIMELS                       0x26U

#define UBX_ID_TIM_TP                           0x01U

#define UBX_ID_MON_VER                          0x04U
#define UBX_MON_VER_BASE_LENGTH                 40U
#define UBX_MON_VER_EXTENSION_LENGTH            30U
#define UBX_MON_VER_MAX_PAYLOAD_LENGTH          512U

#define UBX_ID_CFG_MSG                          0x01U
#define UBX_ID_CFG_TP5                          0x31U

#define UBX_ID_NMEA_ZDA                         0x08U

#define UBX_CFG_MSG_PAYLOAD_LENGTH              8U
#define UBX_CFG_TP5_PAYLOAD_LENGTH              32U

#define UBX_TP5_FLAG_ACTIVE                     (1UL << 0)
#define UBX_TP5_FLAG_LOCK_GNSS_FREQ             (1UL << 1)
#define UBX_TP5_FLAG_IS_FREQ                    (1UL << 3)
#define UBX_TP5_FLAG_IS_LENGTH                  (1UL << 4)
#define UBX_TP5_FLAG_ALIGN_TO_TOW               (1UL << 5)
#define UBX_TP5_FLAG_POLARITY_RISING            (1UL << 6)

#define UBX_NAV_PVT_MIN_LENGTH                  92U
#define UBX_NAV_PVT_YEAR_OFFSET                 4U
#define UBX_NAV_PVT_MONTH_OFFSET                6U
#define UBX_NAV_PVT_DAY_OFFSET                  7U
#define UBX_NAV_PVT_HOUR_OFFSET                 8U
#define UBX_NAV_PVT_MINUTE_OFFSET               9U
#define UBX_NAV_PVT_SECOND_OFFSET               10U
#define UBX_NAV_PVT_VALID_OFFSET                11U
#define UBX_NAV_PVT_FIX_TYPE_OFFSET             20U
#define UBX_NAV_PVT_FLAGS_OFFSET                21U
#define UBX_NAV_PVT_NUM_SV_OFFSET               23U

#define UBX_NAV_PVT_VALID_DATE                  (1U << 0)
#define UBX_NAV_PVT_VALID_TIME                  (1U << 1)
#define UBX_NAV_PVT_VALID_FULLY_RESOLVED        (1U << 2)
#define UBX_NAV_PVT_FLAG_GNSS_FIX_OK            (1U << 0)

#define UBX_NAV_TIMELS_MIN_LENGTH               24U
#define UBX_NAV_TIMELS_CURRENT_LEAP_OFFSET      9U
#define UBX_NAV_TIMELS_LEAP_CHANGE_OFFSET       11U
#define UBX_NAV_TIMELS_TIME_TO_EVENT_OFFSET     12U
#define UBX_NAV_TIMELS_VALID_OFFSET             20U

#define UBX_NAV_TIMELS_VALID_CURRENT_LEAP       (1U << 0)
#define UBX_NAV_TIMELS_VALID_TIME_TO_EVENT      (1U << 1)

#define UBX_TIM_TP_MIN_LENGTH                   16U
#define UBX_TIM_TP_TOW_MS_OFFSET                0U
#define UBX_TIM_TP_TOW_SUB_MS_OFFSET            4U
#define UBX_TIM_TP_QERR_OFFSET                  8U
#define UBX_TIM_TP_WEEK_OFFSET                  12U
#define UBX_TIM_TP_FLAGS_OFFSET                 14U

typedef enum {
    UBX_WAIT_SYNC_1 = 0,
    UBX_WAIT_SYNC_2,
    UBX_WAIT_CLASS,
    UBX_WAIT_ID,
    UBX_WAIT_LENGTH_1,
    UBX_WAIT_LENGTH_2,
    UBX_WAIT_PAYLOAD,
    UBX_WAIT_CK_A,
    UBX_WAIT_CK_B,
} ubx_parse_state_t;

typedef struct {
    ubx_parse_state_t state;
    uint8_t message_class;
    uint8_t message_id;
    uint16_t payload_length;
    uint16_t payload_index;
    uint8_t ck_a;
    uint8_t ck_b;
    uint8_t received_ck_a;
    uint8_t received_ck_b;
    uint8_t payload[UBX_MON_VER_MAX_PAYLOAD_LENGTH];
} ubx_parser_t;

static portMUX_TYPE s_gnss_lock = portMUX_INITIALIZER_UNLOCKED;

static gnss_service_status_t s_status;
static ubx_parser_t s_ubx_parser;

static char s_nmea_line[GNSS_LINE_MAX_LENGTH];
static size_t s_nmea_length;

static int64_t s_last_utc_rx_us;
static int64_t s_last_pvt_rx_us;
static int64_t s_last_tim_tp_rx_us;

static bool s_ack_waiting;
static uint8_t s_ack_expected_class;
static uint8_t s_ack_expected_id;
static esp_err_t s_ack_result;

static uint16_t read_le_u16(const uint8_t *data)
{
    return (uint16_t)data[0] |
           ((uint16_t)data[1] << 8);
}

static uint32_t read_le_u32(const uint8_t *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static int32_t read_le_i32(const uint8_t *data)
{
    return (int32_t)read_le_u32(data);
}

static void write_le_u32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value & 0xFFU);
    data[1] = (uint8_t)((value >> 8) & 0xFFU);
    data[2] = (uint8_t)((value >> 16) & 0xFFU);
    data[3] = (uint8_t)((value >> 24) & 0xFFU);
}

static int64_t days_from_civil(int year, unsigned month, unsigned day)
{
    year -= (month <= 2U) ? 1 : 0;

    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yoe = (unsigned)(year - era * 400);
    const unsigned shifted_month = month > 2U ? month - 3U : month + 9U;
    const unsigned doy = (153U * shifted_month + 2U) / 5U + day - 1U;
    const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;

    return (int64_t)era * 146097LL + (int64_t)doe - 719468LL;
}

static bool datetime_to_epoch(int year,
                              int month,
                              int day,
                              int hour,
                              int minute,
                              int second,
                              int64_t *out_epoch)
{
    if (out_epoch == NULL ||
        year < 2000 ||
        year > 2100 ||
        month < 1 ||
        month > 12 ||
        day < 1 ||
        day > 31 ||
        hour < 0 ||
        hour > 23 ||
        minute < 0 ||
        minute > 59 ||
        second < 0 ||
        second > 60) {
        return false;
    }

    if (second == 60) {
        second = 59;
    }

    *out_epoch =
        days_from_civil(year, (unsigned)month, (unsigned)day) * 86400LL +
        (int64_t)hour * 3600LL +
        (int64_t)minute * 60LL +
        second;

    return true;
}

static bool parse_two_digits(const char *text, int *out_value)
{
    if (text == NULL ||
        out_value == NULL ||
        !isdigit((unsigned char)text[0]) ||
        !isdigit((unsigned char)text[1])) {
        return false;
    }

    *out_value = ((text[0] - '0') * 10) + (text[1] - '0');
    return true;
}

static bool nmea_checksum_valid(const char *line)
{
    if (line == NULL || line[0] != '$') {
        return false;
    }

    const char *asterisk = strchr(line, '*');

    if (asterisk == NULL ||
        !isxdigit((unsigned char)asterisk[1]) ||
        !isxdigit((unsigned char)asterisk[2])) {
        return false;
    }

    uint8_t checksum = 0U;

    for (const char *cursor = line + 1; cursor < asterisk; ++cursor) {
        checksum ^= (uint8_t)*cursor;
    }

    char expected[3] = {
        asterisk[1],
        asterisk[2],
        '\0',
    };

    return checksum == (uint8_t)strtoul(expected, NULL, 16);
}

static bool parse_zda_epoch(const char *line, int64_t *out_epoch)
{
    if (line == NULL || out_epoch == NULL) {
        return false;
    }

    char local_line[GNSS_LINE_MAX_LENGTH];
    const size_t length = strnlen(line, sizeof(local_line));

    if (length == 0U || length >= sizeof(local_line)) {
        return false;
    }

    memcpy(local_line, line, length + 1U);

    char *asterisk = strchr(local_line, '*');

    if (asterisk != NULL) {
        *asterisk = '\0';
    }

    char *save_ptr = NULL;
    char *message = strtok_r(local_line, ",", &save_ptr);

    if (message == NULL) {
        return false;
    }

    const size_t message_length = strlen(message);

    if (message_length < 3U ||
        strcmp(message + message_length - 3U, "ZDA") != 0) {
        return false;
    }

    char *utc_text = strtok_r(NULL, ",", &save_ptr);
    char *day_text = strtok_r(NULL, ",", &save_ptr);
    char *month_text = strtok_r(NULL, ",", &save_ptr);
    char *year_text = strtok_r(NULL, ",", &save_ptr);

    if (utc_text == NULL ||
        day_text == NULL ||
        month_text == NULL ||
        year_text == NULL ||
        strlen(utc_text) < 6U) {
        return false;
    }

    int hour = 0;
    int minute = 0;
    int second = 0;

    if (!parse_two_digits(utc_text, &hour) ||
        !parse_two_digits(utc_text + 2, &minute) ||
        !parse_two_digits(utc_text + 4, &second)) {
        return false;
    }

    return datetime_to_epoch(atoi(year_text),
                             atoi(month_text),
                             atoi(day_text),
                             hour,
                             minute,
                             second,
                             out_epoch);
}

static void process_nmea_line(const char *line)
{
    if (!nmea_checksum_valid(line)) {
        portENTER_CRITICAL(&s_gnss_lock);
        s_status.invalid_messages++;
        portEXIT_CRITICAL(&s_gnss_lock);
        return;
    }

    int64_t epoch = 0;

    if (!parse_zda_epoch(line, &epoch)) {
        return;
    }

    const int64_t now_us = esp_timer_get_time();
    bool use_fallback = false;

    portENTER_CRITICAL(&s_gnss_lock);

    s_status.valid_zda_messages++;

    if (!s_status.utc_from_ubx_pvt ||
        s_last_pvt_rx_us == 0 ||
        now_us - s_last_pvt_rx_us >
            ((int64_t)APP_GNSS_TIMEOUT_SECONDS * 1000000LL)) {
        s_status.utc_valid = true;
        s_status.utc_from_ubx_pvt = false;
        s_status.utc_seconds = epoch;
        s_status.utc_age_us = 0;
        s_status.leap_indicator = APP_LEAP_UNKNOWN;

        s_last_utc_rx_us = now_us;
        use_fallback = true;
    }

    portEXIT_CRITICAL(&s_gnss_lock);

    if (use_fallback) {
        app_state_set_gnss_valid(true,
                                 epoch,
                                 APP_LEAP_UNKNOWN,
                                 0);
    }
}

static void ubx_parser_reset(void)
{
    memset(&s_ubx_parser, 0, sizeof(s_ubx_parser));
    s_ubx_parser.state = UBX_WAIT_SYNC_1;
}

static void ubx_checksum_add(uint8_t byte)
{
    s_ubx_parser.ck_a = (uint8_t)(s_ubx_parser.ck_a + byte);
    s_ubx_parser.ck_b =
        (uint8_t)(s_ubx_parser.ck_b + s_ubx_parser.ck_a);
}

static void handle_ubx_ack(uint8_t message_id,
                           const uint8_t *payload,
                           uint16_t payload_length)
{
    if (payload_length != 2U) {
        return;
    }

    if (message_id == UBX_ID_ACK_ACK) {
        portENTER_CRITICAL(&s_gnss_lock);
        s_status.ubx_ack_count++;
        portEXIT_CRITICAL(&s_gnss_lock);
    } else if (message_id == UBX_ID_ACK_NAK) {
        portENTER_CRITICAL(&s_gnss_lock);
        s_status.ubx_nak_count++;
        portEXIT_CRITICAL(&s_gnss_lock);
    }

    if (s_ack_waiting &&
        payload[0] == s_ack_expected_class &&
        payload[1] == s_ack_expected_id) {
        s_ack_result = message_id == UBX_ID_ACK_ACK ?
            ESP_OK :
            ESP_ERR_INVALID_RESPONSE;

        s_ack_waiting = false;
    }
}

static void handle_ubx_nav_pvt(const uint8_t *payload,
                               uint16_t payload_length)
{
    if (payload_length < UBX_NAV_PVT_MIN_LENGTH) {
        return;
    }

    const int year = (int)read_le_u16(&payload[UBX_NAV_PVT_YEAR_OFFSET]);
    const int month = payload[UBX_NAV_PVT_MONTH_OFFSET];
    const int day = payload[UBX_NAV_PVT_DAY_OFFSET];
    const int hour = payload[UBX_NAV_PVT_HOUR_OFFSET];
    const int minute = payload[UBX_NAV_PVT_MINUTE_OFFSET];
    const int second = payload[UBX_NAV_PVT_SECOND_OFFSET];

    const uint8_t valid_flags = payload[UBX_NAV_PVT_VALID_OFFSET];
    const uint8_t fix_type = payload[UBX_NAV_PVT_FIX_TYPE_OFFSET];
    const uint8_t fix_flags = payload[UBX_NAV_PVT_FLAGS_OFFSET];
    const uint8_t satellites = payload[UBX_NAV_PVT_NUM_SV_OFFSET];

    const bool valid_date =
        (valid_flags & UBX_NAV_PVT_VALID_DATE) != 0U;

    const bool valid_time =
        (valid_flags & UBX_NAV_PVT_VALID_TIME) != 0U;

    const bool fully_resolved =
        (valid_flags & UBX_NAV_PVT_VALID_FULLY_RESOLVED) != 0U;

    const bool fix_valid =
        (fix_flags & UBX_NAV_PVT_FLAG_GNSS_FIX_OK) != 0U &&
        fix_type >= 2U;

    int64_t epoch = 0;

    const bool utc_valid =
        valid_date &&
        valid_time &&
        fully_resolved &&
        fix_valid &&
        datetime_to_epoch(year,
                          month,
                          day,
                          hour,
                          minute,
                          second,
                          &epoch);

    const int64_t now_us = esp_timer_get_time();
    app_leap_indicator_t leap_indicator;

    portENTER_CRITICAL(&s_gnss_lock);

    s_status.ubx_nav_pvt_messages++;
    s_status.gnss_fix_valid = fix_valid;
    s_status.gnss_time_fully_resolved = fully_resolved;
    s_status.fix_type = fix_type;
    s_status.satellites_used = satellites;

    leap_indicator = s_status.leap_indicator;

    if (utc_valid) {
        s_status.utc_valid = true;
        s_status.utc_from_ubx_pvt = true;
        s_status.utc_seconds = epoch;
        s_status.utc_age_us = 0;

        s_last_pvt_rx_us = now_us;
        s_last_utc_rx_us = now_us;
    } else if (s_status.utc_from_ubx_pvt) {
        s_status.utc_valid = false;
    }

    portEXIT_CRITICAL(&s_gnss_lock);

    app_state_set_gnss_valid(utc_valid,
                             utc_valid ? epoch : 0,
                             utc_valid ? leap_indicator :
                                         APP_LEAP_UNKNOWN,
                             0);
}

static void handle_ubx_nav_timels(const uint8_t *payload,
                                  uint16_t payload_length)
{
    if (payload_length < UBX_NAV_TIMELS_MIN_LENGTH) {
        return;
    }

    const int8_t current_leap_seconds =
        (int8_t)payload[UBX_NAV_TIMELS_CURRENT_LEAP_OFFSET];

    const int8_t leap_change =
        (int8_t)payload[UBX_NAV_TIMELS_LEAP_CHANGE_OFFSET];

    const int32_t seconds_to_event =
        read_le_i32(&payload[UBX_NAV_TIMELS_TIME_TO_EVENT_OFFSET]);

    const uint8_t valid_flags =
        payload[UBX_NAV_TIMELS_VALID_OFFSET];

    const bool current_leap_valid =
        (valid_flags & UBX_NAV_TIMELS_VALID_CURRENT_LEAP) != 0U;

    const bool event_time_valid =
        (valid_flags & UBX_NAV_TIMELS_VALID_TIME_TO_EVENT) != 0U;

    /*
     * LEA-M8T receivers can report a usable current leap-second value before
     * validCurrLs is asserted. Accept only the bounded no-pending-leap case:
     *
     * - Current leap value is plausible.
     * - No insertion or deletion is pending.
     * - The next event is more than 24 hours away.
     */
    const bool bounded_current_leap_fallback =
        current_leap_seconds >= 0 &&
        current_leap_seconds <= 64 &&
        leap_change == 0 &&
        seconds_to_event > 86400;

    const bool leap_information_usable =
        current_leap_valid || bounded_current_leap_fallback;

    app_leap_indicator_t leap_indicator = APP_LEAP_UNKNOWN;

    if (leap_information_usable) {
        leap_indicator = APP_LEAP_NO_WARNING;

        if (event_time_valid &&
            seconds_to_event > 0 &&
            leap_change > 0) {
            leap_indicator = APP_LEAP_ADD_SECOND;
        } else if (event_time_valid &&
                   seconds_to_event > 0 &&
                   leap_change < 0) {
            leap_indicator = APP_LEAP_DELETE_SECOND;
        }
    }

    portENTER_CRITICAL(&s_gnss_lock);

    s_status.ubx_nav_timels_messages++;
    s_status.leap_information_valid = leap_information_usable;
    s_status.current_leap_seconds = current_leap_seconds;
    s_status.pending_leap_change = leap_change;
    s_status.seconds_to_leap_event = seconds_to_event;
    s_status.leap_indicator = leap_indicator;

    portEXIT_CRITICAL(&s_gnss_lock);

    if (!current_leap_valid && bounded_current_leap_fallback) {
        ESP_LOGW(TAG,
                 "NAV-TIMELS fallback: current_ls=%d event_in=%" PRId32
                 " s",
                 current_leap_seconds,
                 seconds_to_event);
    }
}

static void handle_ubx_tim_tp(const uint8_t *payload,
                              uint16_t payload_length)
{
    if (payload_length < UBX_TIM_TP_MIN_LENGTH) {
        return;
    }

    const uint32_t tow_ms =
        read_le_u32(&payload[UBX_TIM_TP_TOW_MS_OFFSET]);

    const int32_t tow_sub_ms =
        read_le_i32(&payload[UBX_TIM_TP_TOW_SUB_MS_OFFSET]);

    /*
     * UBX-TIM-TP qErr is in picoseconds. The legacy field name in
     * gnss_service_status_t is retained for compatibility.
     */
    const int32_t qerr_ps =
        read_le_i32(&payload[UBX_TIM_TP_QERR_OFFSET]);

    const uint16_t week =
        read_le_u16(&payload[UBX_TIM_TP_WEEK_OFFSET]);

    const uint8_t flags =
        payload[UBX_TIM_TP_FLAGS_OFFSET];

    const int64_t now_us = esp_timer_get_time();

    portENTER_CRITICAL(&s_gnss_lock);

    s_status.ubx_tim_tp_messages++;
    s_status.timing_pulse_valid = true;
    s_status.timing_week = week;
    s_status.timing_tow_ms = tow_ms;
    s_status.timing_tow_sub_ms = tow_sub_ms;
    s_status.timing_quantization_error_ns = qerr_ps;
    s_status.timing_pulse_flags = flags;
    s_status.timing_pulse_age_us = 0;

    s_last_tim_tp_rx_us = now_us;

    portEXIT_CRITICAL(&s_gnss_lock);
}


static void copy_ubx_text_field(char *dst, size_t dst_size,
                                const uint8_t *src, size_t src_size)
{
    if (dst == NULL || dst_size == 0U) {
        return;
    }

    size_t length = 0U;
    while (length < src_size && src[length] != 0U) {
        ++length;
    }
    while (length > 0U && src[length - 1U] == ' ') {
        --length;
    }

    if (length >= dst_size) {
        length = dst_size - 1U;
    }

    memcpy(dst, src, length);
    dst[length] = '\0';
}

static void handle_ubx_mon_ver(const uint8_t *payload, uint16_t payload_length)
{
    if (payload == NULL || payload_length < UBX_MON_VER_BASE_LENGTH) {
        portENTER_CRITICAL(&s_gnss_lock);
        s_status.ubx_frames_invalid_length++;
        portEXIT_CRITICAL(&s_gnss_lock);
        return;
    }

    char software[31] = {0};
    char hardware[11] = {0};
    char model[32] = {0};

    copy_ubx_text_field(software, sizeof(software), &payload[0], 30U);
    copy_ubx_text_field(hardware, sizeof(hardware), &payload[30], 10U);

    for (uint16_t offset = UBX_MON_VER_BASE_LENGTH;
         offset + UBX_MON_VER_EXTENSION_LENGTH <= payload_length;
         offset += UBX_MON_VER_EXTENSION_LENGTH) {
        char extension[UBX_MON_VER_EXTENSION_LENGTH + 1U] = {0};
        copy_ubx_text_field(extension, sizeof(extension),
                            &payload[offset], UBX_MON_VER_EXTENSION_LENGTH);
        if (strncmp(extension, "MOD=", 4U) == 0 && extension[4] != '\0') {
            snprintf(model, sizeof(model), "%s", &extension[4]);
            break;
        }
    }

    /* Older M8 firmware may omit the MOD= extension. In that case expose the
     * receiver's own HW version rather than inventing a module model. */
    if (model[0] == '\0' && hardware[0] != '\0') {
        snprintf(model, sizeof(model), "%s", hardware);
    }

    portENTER_CRITICAL(&s_gnss_lock);
    snprintf(s_status.receiver_model, sizeof(s_status.receiver_model), "%s", model);
    snprintf(s_status.receiver_software_version,
             sizeof(s_status.receiver_software_version), "%s", software);
    snprintf(s_status.receiver_hardware_version,
             sizeof(s_status.receiver_hardware_version), "%s", hardware);
    s_status.receiver_identity_valid =
        s_status.receiver_software_version[0] != '\0' ||
        s_status.receiver_hardware_version[0] != '\0';
    portEXIT_CRITICAL(&s_gnss_lock);

    ESP_LOGI(TAG, "UBX receiver identity: model=%s sw=%s hw=%s",
             model[0] != '\0' ? model : "unknown",
             software[0] != '\0' ? software : "unknown",
             hardware[0] != '\0' ? hardware : "unknown");
}

static void dispatch_ubx_frame(uint8_t message_class,
                               uint8_t message_id,
                               const uint8_t *payload,
                               uint16_t payload_length)
{
    portENTER_CRITICAL(&s_gnss_lock);
    s_status.ubx_frames_valid++;
    portEXIT_CRITICAL(&s_gnss_lock);

    if (message_class == UBX_CLASS_ACK &&
        (message_id == UBX_ID_ACK_ACK ||
         message_id == UBX_ID_ACK_NAK)) {
        handle_ubx_ack(message_id, payload, payload_length);
        return;
    }

    if (message_class == UBX_CLASS_NAV &&
        message_id == UBX_ID_NAV_PVT) {
        handle_ubx_nav_pvt(payload, payload_length);
        return;
    }

    if (message_class == UBX_CLASS_NAV &&
        message_id == UBX_ID_NAV_TIMELS) {
        handle_ubx_nav_timels(payload, payload_length);
        return;
    }

    if (message_class == UBX_CLASS_TIM &&
        message_id == UBX_ID_TIM_TP) {
        handle_ubx_tim_tp(payload, payload_length);
        return;
    }

    if (message_class == UBX_CLASS_MON &&
        message_id == UBX_ID_MON_VER) {
        handle_ubx_mon_ver(payload, payload_length);
        return;
    }

    portENTER_CRITICAL(&s_gnss_lock);
    s_status.ubx_frames_unsupported++;
    portEXIT_CRITICAL(&s_gnss_lock);
}

static void ubx_parser_consume(uint8_t byte)
{
    switch (s_ubx_parser.state) {
    case UBX_WAIT_SYNC_1:
        if (byte == UBX_SYNC_1) {
            s_ubx_parser.state = UBX_WAIT_SYNC_2;
        }
        break;

    case UBX_WAIT_SYNC_2:
        if (byte == UBX_SYNC_2) {
            s_ubx_parser.state = UBX_WAIT_CLASS;
        } else if (byte == UBX_SYNC_1) {
            s_ubx_parser.state = UBX_WAIT_SYNC_2;
        } else {
            s_ubx_parser.state = UBX_WAIT_SYNC_1;
        }
        break;

    case UBX_WAIT_CLASS:
        s_ubx_parser.message_class = byte;
        ubx_checksum_add(byte);
        s_ubx_parser.state = UBX_WAIT_ID;
        break;

    case UBX_WAIT_ID:
        s_ubx_parser.message_id = byte;
        ubx_checksum_add(byte);
        s_ubx_parser.state = UBX_WAIT_LENGTH_1;
        break;

    case UBX_WAIT_LENGTH_1:
        s_ubx_parser.payload_length = byte;
        ubx_checksum_add(byte);
        s_ubx_parser.state = UBX_WAIT_LENGTH_2;
        break;

    case UBX_WAIT_LENGTH_2:
        s_ubx_parser.payload_length |= ((uint16_t)byte << 8);
        ubx_checksum_add(byte);

        if (s_ubx_parser.payload_length >
            UBX_MON_VER_MAX_PAYLOAD_LENGTH) {
            portENTER_CRITICAL(&s_gnss_lock);
            s_status.ubx_frames_invalid_length++;
            portEXIT_CRITICAL(&s_gnss_lock);

            ubx_parser_reset();
            break;
        }

        s_ubx_parser.payload_index = 0U;

        s_ubx_parser.state =
            s_ubx_parser.payload_length == 0U ?
                UBX_WAIT_CK_A :
                UBX_WAIT_PAYLOAD;
        break;

    case UBX_WAIT_PAYLOAD:
        s_ubx_parser.payload[s_ubx_parser.payload_index++] = byte;
        ubx_checksum_add(byte);

        if (s_ubx_parser.payload_index >=
            s_ubx_parser.payload_length) {
            s_ubx_parser.state = UBX_WAIT_CK_A;
        }
        break;

    case UBX_WAIT_CK_A:
        s_ubx_parser.received_ck_a = byte;
        s_ubx_parser.state = UBX_WAIT_CK_B;
        break;

    case UBX_WAIT_CK_B:
        s_ubx_parser.received_ck_b = byte;

        if (s_ubx_parser.received_ck_a == s_ubx_parser.ck_a &&
            s_ubx_parser.received_ck_b == s_ubx_parser.ck_b) {
            dispatch_ubx_frame(s_ubx_parser.message_class,
                               s_ubx_parser.message_id,
                               s_ubx_parser.payload,
                               s_ubx_parser.payload_length);
        } else {
            portENTER_CRITICAL(&s_gnss_lock);
            s_status.ubx_frames_invalid_checksum++;
            portEXIT_CRITICAL(&s_gnss_lock);
        }

        ubx_parser_reset();
        break;

    default:
        ubx_parser_reset();
        break;
    }
}

static esp_err_t ubx_write_frame(uint8_t message_class,
                                 uint8_t message_id,
                                 const uint8_t *payload,
                                 uint16_t payload_length)
{
    uint8_t header[6] = {
        UBX_SYNC_1,
        UBX_SYNC_2,
        message_class,
        message_id,
        (uint8_t)(payload_length & 0xFFU),
        (uint8_t)((payload_length >> 8) & 0xFFU),
    };

    uint8_t ck_a = 0U;
    uint8_t ck_b = 0U;

    for (size_t index = 2U; index < sizeof(header); ++index) {
        ck_a = (uint8_t)(ck_a + header[index]);
        ck_b = (uint8_t)(ck_b + ck_a);
    }

    for (uint16_t index = 0U; index < payload_length; ++index) {
        ck_a = (uint8_t)(ck_a + payload[index]);
        ck_b = (uint8_t)(ck_b + ck_a);
    }

    const uint8_t checksum[2] = {
        ck_a,
        ck_b,
    };

    const uart_port_t uart_num = (uart_port_t)APP_GNSS_UART_NUM;

    if (uart_write_bytes(uart_num, header, sizeof(header)) !=
        (int)sizeof(header)) {
        return ESP_FAIL;
    }

    if (payload_length > 0U &&
        uart_write_bytes(uart_num, payload, payload_length) !=
        (int)payload_length) {
        return ESP_FAIL;
    }

    if (uart_write_bytes(uart_num, checksum, sizeof(checksum)) !=
        (int)sizeof(checksum)) {
        return ESP_FAIL;
    }

    return uart_wait_tx_done(uart_num, pdMS_TO_TICKS(250U));
}

static void process_received_byte(uint8_t byte)
{
    if (s_ubx_parser.state != UBX_WAIT_SYNC_1 ||
        byte == UBX_SYNC_1) {
        s_nmea_length = 0U;
        ubx_parser_consume(byte);
        return;
    }

    if (byte == '$') {
        s_nmea_length = 0U;
        s_nmea_line[s_nmea_length++] = '$';
        return;
    }

    if (s_nmea_length == 0U) {
        return;
    }

    if (byte == '\r') {
        return;
    }

    if (byte == '\n') {
        s_nmea_line[s_nmea_length] = '\0';

        if (s_nmea_length > 0U) {
            process_nmea_line(s_nmea_line);
        }

        s_nmea_length = 0U;
        return;
    }

    if (s_nmea_length < sizeof(s_nmea_line) - 1U) {
        s_nmea_line[s_nmea_length++] = (char)byte;
    } else {
        s_nmea_length = 0U;

        portENTER_CRITICAL(&s_gnss_lock);
        s_status.invalid_messages++;
        portEXIT_CRITICAL(&s_gnss_lock);
    }
}

static esp_err_t ubx_send_and_wait_ack(uint8_t message_class,
                                       uint8_t message_id,
                                       const uint8_t *payload,
                                       uint16_t payload_length)
{
    const uart_port_t uart_num = (uart_port_t)APP_GNSS_UART_NUM;
    esp_err_t result = ESP_FAIL;

    for (uint32_t attempt = 0U;
         attempt <= APP_GNSS_UBX_COMMAND_RETRIES;
         ++attempt) {
        (void)uart_flush_input(uart_num);

        s_ack_waiting = true;
        s_ack_expected_class = message_class;
        s_ack_expected_id = message_id;
        s_ack_result = ESP_ERR_TIMEOUT;

        result = ubx_write_frame(message_class,
                                 message_id,
                                 payload,
                                 payload_length);

        if (result != ESP_OK) {
            s_ack_waiting = false;
            continue;
        }

        const int64_t deadline_us =
            esp_timer_get_time() +
            ((int64_t)APP_GNSS_UBX_ACK_TIMEOUT_MS * 1000LL);

        while (s_ack_waiting &&
               esp_timer_get_time() < deadline_us) {
            uint8_t receive_buffer[64];

            const int received = uart_read_bytes(
                uart_num,
                receive_buffer,
                sizeof(receive_buffer),
                pdMS_TO_TICKS(25U));

            for (int index = 0; index < received; ++index) {
                process_received_byte(receive_buffer[index]);
            }
        }

        if (!s_ack_waiting && s_ack_result == ESP_OK) {
            return ESP_OK;
        }

        s_ack_waiting = false;
        result = s_ack_result;
    }

    portENTER_CRITICAL(&s_gnss_lock);
    s_status.ubx_configuration_failures++;
    portEXIT_CRITICAL(&s_gnss_lock);

    return result;
}

static esp_err_t ubx_configure_message_rate(uint8_t message_class,
                                            uint8_t message_id,
                                            uint8_t uart1_rate)
{
    const uint8_t payload[UBX_CFG_MSG_PAYLOAD_LENGTH] = {
        message_class,
        message_id,
        0U,
        uart1_rate,
        0U,
        0U,
        0U,
        0U,
    };

    return ubx_send_and_wait_ack(UBX_CLASS_CFG,
                                 UBX_ID_CFG_MSG,
                                 payload,
                                 sizeof(payload));
}

static esp_err_t ubx_configure_tp1(void)
{
    uint8_t payload[UBX_CFG_TP5_PAYLOAD_LENGTH] = {0};

    payload[0] = 0U;
    payload[1] = 1U;

    write_le_u32(&payload[8], APP_GNSS_TP1_FREQUENCY_HZ);
    write_le_u32(&payload[12], APP_GNSS_TP1_FREQUENCY_HZ);

    write_le_u32(&payload[16], APP_GNSS_TP1_PULSE_LENGTH_US);
    write_le_u32(&payload[20], APP_GNSS_TP1_PULSE_LENGTH_US);

    const uint32_t flags =
        UBX_TP5_FLAG_ACTIVE |
        UBX_TP5_FLAG_LOCK_GNSS_FREQ |
        UBX_TP5_FLAG_IS_FREQ |
        UBX_TP5_FLAG_IS_LENGTH |
        UBX_TP5_FLAG_ALIGN_TO_TOW |
        UBX_TP5_FLAG_POLARITY_RISING;

    write_le_u32(&payload[28], flags);

    return ubx_send_and_wait_ack(UBX_CLASS_CFG,
                                 UBX_ID_CFG_TP5,
                                 payload,
                                 sizeof(payload));
}


static void ubx_poll_mon_ver(void)
{
    const uart_port_t uart_num = (uart_port_t)APP_GNSS_UART_NUM;

    if (ubx_write_frame(UBX_CLASS_MON, UBX_ID_MON_VER, NULL, 0U) != ESP_OK) {
        ESP_LOGW(TAG, "UBX-MON-VER poll transmit failed");
        return;
    }

    const int64_t deadline_us = esp_timer_get_time() + 750000LL;
    while (esp_timer_get_time() < deadline_us) {
        uint8_t receive_buffer[96];
        const int received = uart_read_bytes(uart_num, receive_buffer,
                                             sizeof(receive_buffer),
                                             pdMS_TO_TICKS(25U));
        for (int index = 0; index < received; ++index) {
            process_received_byte(receive_buffer[index]);
        }

        portENTER_CRITICAL(&s_gnss_lock);
        const bool identity_valid = s_status.receiver_identity_valid;
        portEXIT_CRITICAL(&s_gnss_lock);
        if (identity_valid) {
            return;
        }
    }

    ESP_LOGW(TAG, "UBX-MON-VER identity response not received");
}

static void gnss_configure_receiver(void)
{
    portENTER_CRITICAL(&s_gnss_lock);
    s_status.ubx_configuration_attempted = true;
    portEXIT_CRITICAL(&s_gnss_lock);

    bool complete = true;
    esp_err_t err;

    err = ubx_configure_message_rate(UBX_CLASS_NAV,
                                     UBX_ID_NAV_PVT,
                                     1U);

    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "UBX-NAV-PVT configuration failed: %s",
                 esp_err_to_name(err));
        complete = false;
    }

    err = ubx_configure_message_rate(UBX_CLASS_NAV,
                                     UBX_ID_NAV_TIMELS,
                                     1U);

    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "UBX-NAV-TIMELS configuration failed: %s",
                 esp_err_to_name(err));
        complete = false;
    }

    err = ubx_configure_message_rate(UBX_CLASS_TIM,
                                     UBX_ID_TIM_TP,
                                     1U);

    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "UBX-TIM-TP configuration failed: %s",
                 esp_err_to_name(err));
        complete = false;
    }

    err = ubx_configure_message_rate(UBX_CLASS_NMEA,
                                     UBX_ID_NMEA_ZDA,
                                     1U);

    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "NMEA-ZDA configuration failed: %s",
                 esp_err_to_name(err));
        complete = false;
    }

    if (APP_GNSS_CONFIGURE_TIMEPULSE) {
        portENTER_CRITICAL(&s_gnss_lock);
        s_status.ubx_timepulse_configuration_attempted = true;
        portEXIT_CRITICAL(&s_gnss_lock);

        err = ubx_configure_tp1();

        if (err == ESP_OK) {
            portENTER_CRITICAL(&s_gnss_lock);
            s_status.ubx_timepulse_configuration_complete = true;
            portEXIT_CRITICAL(&s_gnss_lock);
        } else {
            ESP_LOGW(TAG,
                     "TIMEPULSE 1 configuration failed: %s",
                     esp_err_to_name(err));
            complete = false;
        }
    }

    portENTER_CRITICAL(&s_gnss_lock);
    s_status.ubx_configuration_complete = complete;
    portEXIT_CRITICAL(&s_gnss_lock);

    if (complete) {
        ESP_LOGI(TAG, "LEA-M8T UBX configuration acknowledged");
    } else {
        ESP_LOGW(TAG,
                 "LEA-M8T UBX configuration incomplete; "
                 "NMEA fallback remains enabled");
    }
}

static void gnss_update_staleness(void)
{
    const int64_t now_us = esp_timer_get_time();

    bool utc_became_stale = false;
    int64_t utc_age_us = -1;

    portENTER_CRITICAL(&s_gnss_lock);

    if (s_status.utc_valid && s_last_utc_rx_us > 0) {
        utc_age_us = now_us - s_last_utc_rx_us;

        if (utc_age_us < 0) {
            utc_age_us = 0;
        }

        s_status.utc_age_us = utc_age_us;

        if (utc_age_us >
            ((int64_t)APP_GNSS_TIMEOUT_SECONDS * 1000000LL)) {
            s_status.utc_valid = false;
            s_status.utc_from_ubx_pvt = false;
            utc_became_stale = true;
        }
    }

    if (s_status.timing_pulse_valid && s_last_tim_tp_rx_us > 0) {
        int64_t timing_age_us = now_us - s_last_tim_tp_rx_us;

        if (timing_age_us < 0) {
            timing_age_us = 0;
        }

        s_status.timing_pulse_age_us = timing_age_us;

        if (timing_age_us >
            ((int64_t)APP_GNSS_TIMEOUT_SECONDS * 1000000LL)) {
            s_status.timing_pulse_valid = false;
        }
    }

    portEXIT_CRITICAL(&s_gnss_lock);

    if (utc_became_stale) {
        app_state_set_gnss_valid(false,
                                 0,
                                 APP_LEAP_UNKNOWN,
                                 utc_age_us);

        ESP_LOGW(TAG, "GNSS UTC state became stale");
    }
}

static void gnss_task(void *arg)
{
    (void)arg;

    uint8_t receive_buffer[GNSS_READ_BUFFER_SIZE];
    const uart_port_t uart_num = (uart_port_t)APP_GNSS_UART_NUM;

    while (true) {
        const int received = uart_read_bytes(uart_num,
                                             receive_buffer,
                                             sizeof(receive_buffer),
                                             pdMS_TO_TICKS(250U));

        if (received > 0) {
            portENTER_CRITICAL(&s_gnss_lock);
            s_status.uart_bytes_received += (uint32_t)received;
            portEXIT_CRITICAL(&s_gnss_lock);

            for (int index = 0; index < received; ++index) {
                process_received_byte(receive_buffer[index]);
            }
        }

        gnss_update_staleness();
    }
}

esp_err_t gnss_service_init(void)
{
    if (s_status.initialized) {
        return ESP_OK;
    }

    const uart_port_t uart_num = (uart_port_t)APP_GNSS_UART_NUM;

    const uart_config_t uart_config = {
        .baud_rate = APP_GNSS_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_LOGI(TAG,
             "GNSS UART configuration: UART%d TX=%d RX=%d baud=%d",
             APP_GNSS_UART_NUM,
             APP_GNSS_UART_TX_GPIO,
             APP_GNSS_UART_RX_GPIO,
             APP_GNSS_UART_BAUD);

    ESP_RETURN_ON_ERROR(
        uart_driver_install(uart_num,
                            APP_GNSS_UART_RX_BUFFER_SIZE,
                            APP_GNSS_UART_TX_BUFFER_SIZE,
                            0,
                            NULL,
                            0),
        TAG,
        "install GNSS UART driver");

    ESP_RETURN_ON_ERROR(
        uart_param_config(uart_num, &uart_config),
        TAG,
        "configure GNSS UART");

    ESP_RETURN_ON_ERROR(
        uart_set_pin(uart_num,
                     APP_GNSS_UART_TX_GPIO,
                     APP_GNSS_UART_RX_GPIO,
                     UART_PIN_NO_CHANGE,
                     UART_PIN_NO_CHANGE),
        TAG,
        "assign GNSS UART pins");

    ubx_parser_reset();

    portENTER_CRITICAL(&s_gnss_lock);

    memset(&s_status, 0, sizeof(s_status));
    s_status.initialized = true;
    s_status.leap_indicator = APP_LEAP_UNKNOWN;

    portEXIT_CRITICAL(&s_gnss_lock);

    s_nmea_length = 0U;
    s_last_utc_rx_us = 0;
    s_last_pvt_rx_us = 0;
    s_last_tim_tp_rx_us = 0;

    s_ack_waiting = false;
    s_ack_expected_class = 0U;
    s_ack_expected_id = 0U;
    s_ack_result = ESP_ERR_TIMEOUT;

    if (APP_GNSS_CONFIGURE_UBX_ON_BOOT) {
        gnss_configure_receiver();
    } else {
        ESP_LOGW(TAG, "UBX startup configuration disabled");
    }

    /* MON-VER is a read-only poll and does not alter receiver configuration. */
    ubx_poll_mon_ver();

    const BaseType_t task_created = xTaskCreate(
        gnss_task,
        "gnss_service",
        APP_GNSS_TASK_STACK_SIZE,
        NULL,
        APP_GNSS_TASK_PRIORITY,
        NULL);

    if (task_created != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG,
             "LEA-M8T GNSS parser active: UART%d RX=%d TX=%d",
             APP_GNSS_UART_NUM,
             APP_GNSS_UART_RX_GPIO,
             APP_GNSS_UART_TX_GPIO);

    return ESP_OK;
}

bool gnss_service_get_status(gnss_service_status_t *out_status)
{
    if (out_status == NULL) {
        return false;
    }

    gnss_service_status_t local_status;

    portENTER_CRITICAL(&s_gnss_lock);
    local_status = s_status;
    portEXIT_CRITICAL(&s_gnss_lock);

    const int64_t now_us = esp_timer_get_time();

    if (local_status.utc_valid && s_last_utc_rx_us > 0) {
        const int64_t age_us = now_us - s_last_utc_rx_us;
        local_status.utc_age_us = age_us >= 0 ? age_us : 0;
    }

    if (local_status.timing_pulse_valid && s_last_tim_tp_rx_us > 0) {
        const int64_t age_us = now_us - s_last_tim_tp_rx_us;
        local_status.timing_pulse_age_us = age_us >= 0 ? age_us : 0;
    }

    *out_status = local_status;

    return true;
}