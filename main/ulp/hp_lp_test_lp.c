#include <stdint.h>

#include "esp_err.h"

#include "ulp_lp_core_gpio.h"
#include "ulp_lp_core_interrupts.h"
#include "ulp_lp_core_lp_timer_shared.h"
#include "ulp_lp_core_mailbox.h"
#include "ulp_lp_core_utils.h"

#define HP_LP_PPS_GPIO LP_IO_NUM_4

#define HP_LP_CMD_MAILBOX_PROOF          ((lp_message_t)0x1234)
#define HP_LP_CMD_SET_PPS_EXPECTED_TICKS ((lp_message_t)0x2000)

#define HP_LP_PPS_TOLERANCE_DIVISOR 100U

/*
 * Approximately 10 ms at the 40 MHz LP CPU clock.
 *
 * This timeout exists only to return execution periodically to the LP
 * main loop. PPS watchdog timing itself uses the RTC slow timer.
 */
#define HP_LP_MAILBOX_POLL_CYCLES 400000

/*
 * PPS watchdog loss threshold = 2.5 calibrated PPS periods.
 */
#define HP_LP_PPS_WATCHDOG_NUMERATOR   5ULL
#define HP_LP_PPS_WATCHDOG_DENOMINATOR 2ULL

#define HP_LP_PPS_HEALTH_UNKNOWN 0U
#define HP_LP_PPS_HEALTH_HEALTHY 1U
#define HP_LP_PPS_HEALTH_LOST    2U

volatile uint32_t hp_lp_magic = 0;
volatile uint32_t hp_lp_counter = 0;
volatile uint32_t hp_lp_pps_count = 0;

/*
 * HP-visible coherent telemetry sequence.
 *
 * The LP main loop is the sole writer of this sequence counter and of
 * the exported telemetry fields protected by it.
 *
 * Odd  = publishing.
 * Even = stable.
 */
volatile uint32_t hp_lp_pps_telemetry_seq = 0;

volatile uint32_t hp_lp_pps_last_tick_lo = 0;
volatile uint32_t hp_lp_pps_last_tick_hi = 0;

volatile uint32_t hp_lp_pps_period_ticks_lo = 0;
volatile uint32_t hp_lp_pps_period_ticks_hi = 0;

volatile uint32_t hp_lp_pps_interval_count = 0;

/*
 * Calibrated expected one-second RTC slow-clock interval supplied by HP.
 */
volatile uint32_t hp_lp_pps_expected_ticks = 0;

/*
 * PPS interval qualification telemetry.
 */
volatile uint32_t hp_lp_pps_period_error_ticks = 0;
volatile uint32_t hp_lp_pps_interval_valid = 0;
volatile uint32_t hp_lp_pps_valid_interval_count = 0;
volatile uint32_t hp_lp_pps_invalid_interval_count = 0;

/*
 * Autonomous LP PPS watchdog telemetry.
 */
volatile uint32_t hp_lp_pps_health =
    HP_LP_PPS_HEALTH_UNKNOWN;

volatile uint32_t hp_lp_pps_watchdog_age_ticks_lo = 0;
volatile uint32_t hp_lp_pps_watchdog_age_ticks_hi = 0;

volatile uint32_t hp_lp_pps_watchdog_timeout_ticks_lo = 0;
volatile uint32_t hp_lp_pps_watchdog_timeout_ticks_hi = 0;

volatile uint32_t hp_lp_pps_loss_count = 0;
volatile uint32_t hp_lp_pps_recovery_count = 0;

/*
 * LP PPS ISR execution-time telemetry.
 *
 * Raw values are LP CPU cycles measured from ISR entry to completion of
 * the existing PPS ISR work. The LP main loop remains the sole publisher
 * of HP-visible coherent telemetry.
 */
volatile uint32_t hp_lp_pps_isr_timing_sample_count = 0;
volatile uint32_t hp_lp_pps_isr_latest_cycles = 0;
volatile uint32_t hp_lp_pps_isr_min_cycles = 0;
volatile uint32_t hp_lp_pps_isr_max_cycles = 0;
volatile uint32_t hp_lp_pps_isr_sum_cycles_lo = 0;
volatile uint32_t hp_lp_pps_isr_sum_cycles_hi = 0;

/*
 * ISR-owned raw PPS state.
 *
 * The GPIO ISR updates only these raw values. It does not touch the
 * HP-visible telemetry sequence counter.
 */
static volatile uint32_t s_raw_pps_generation = 0;
static volatile uint64_t s_raw_last_pps_tick = 0;
static volatile uint64_t s_raw_period_ticks = 0;
static volatile uint32_t s_raw_pps_count = 0;

static volatile uint32_t s_raw_isr_timing_sample_count = 0;
static volatile uint32_t s_raw_isr_latest_cycles = 0;
static volatile uint32_t s_raw_isr_min_cycles = 0;
static volatile uint32_t s_raw_isr_max_cycles = 0;
static volatile uint64_t s_raw_isr_sum_cycles = 0;

/*
 * LP-main-loop private processed state.
 */
static uint32_t s_processed_generation = 0;

static uint64_t s_last_tick = 0;
static uint64_t s_period_ticks = 0;

static uint32_t s_interval_count = 0;

static uint32_t s_period_error_ticks = 0;
static uint32_t s_interval_valid = 0;
static uint32_t s_valid_interval_count = 0;
static uint32_t s_invalid_interval_count = 0;

static uint32_t s_health =
    HP_LP_PPS_HEALTH_UNKNOWN;

static uint64_t s_watchdog_age_ticks = 0;
static uint64_t s_watchdog_timeout_ticks = 0;

static uint32_t s_loss_count = 0;
static uint32_t s_recovery_count = 0;

static uint32_t s_isr_timing_sample_count = 0;
static uint32_t s_isr_latest_cycles = 0;
static uint32_t s_isr_min_cycles = 0;
static uint32_t s_isr_max_cycles = 0;
static uint64_t s_isr_sum_cycles = 0;

static void hp_lp_publish_telemetry(void)
{
    /*
     * Sole telemetry sequence-counter writer.
     */
    hp_lp_pps_telemetry_seq++;

    hp_lp_pps_last_tick_lo =
        (uint32_t)(
            s_last_tick &
            0xFFFFFFFFULL);

    hp_lp_pps_last_tick_hi =
        (uint32_t)(
            s_last_tick >>
            32);

    hp_lp_pps_period_ticks_lo =
        (uint32_t)(
            s_period_ticks &
            0xFFFFFFFFULL);

    hp_lp_pps_period_ticks_hi =
        (uint32_t)(
            s_period_ticks >>
            32);

    hp_lp_pps_interval_count =
        s_interval_count;

    hp_lp_pps_period_error_ticks =
        s_period_error_ticks;

    hp_lp_pps_interval_valid =
        s_interval_valid;

    hp_lp_pps_valid_interval_count =
        s_valid_interval_count;

    hp_lp_pps_invalid_interval_count =
        s_invalid_interval_count;

    hp_lp_pps_health =
        s_health;

    hp_lp_pps_watchdog_age_ticks_lo =
        (uint32_t)(
            s_watchdog_age_ticks &
            0xFFFFFFFFULL);

    hp_lp_pps_watchdog_age_ticks_hi =
        (uint32_t)(
            s_watchdog_age_ticks >>
            32);

    hp_lp_pps_watchdog_timeout_ticks_lo =
        (uint32_t)(
            s_watchdog_timeout_ticks &
            0xFFFFFFFFULL);

    hp_lp_pps_watchdog_timeout_ticks_hi =
        (uint32_t)(
            s_watchdog_timeout_ticks >>
            32);

    hp_lp_pps_loss_count =
        s_loss_count;

    hp_lp_pps_recovery_count =
        s_recovery_count;

    hp_lp_pps_isr_timing_sample_count =
        s_isr_timing_sample_count;

    hp_lp_pps_isr_latest_cycles =
        s_isr_latest_cycles;

    hp_lp_pps_isr_min_cycles =
        s_isr_min_cycles;

    hp_lp_pps_isr_max_cycles =
        s_isr_max_cycles;

    hp_lp_pps_isr_sum_cycles_lo =
        (uint32_t)(
            s_isr_sum_cycles &
            0xFFFFFFFFULL);

    hp_lp_pps_isr_sum_cycles_hi =
        (uint32_t)(
            s_isr_sum_cycles >>
            32);

    hp_lp_pps_telemetry_seq++;
}

static void hp_lp_process_new_pps(void)
{
    const uint32_t generation =
        s_raw_pps_generation;

    if (generation ==
        s_processed_generation) {
        return;
    }

    /*
     * Snapshot ISR-owned raw state.
     *
     * If another PPS ISR occurs during the copy, generation changes and
     * this sample is retried on the next LP-main-loop iteration.
     */
    const uint64_t last_tick =
        s_raw_last_pps_tick;

    const uint64_t period_ticks =
        s_raw_period_ticks;

    const uint32_t raw_count =
        s_raw_pps_count;

    const uint32_t isr_timing_sample_count =
        s_raw_isr_timing_sample_count;

    const uint32_t isr_latest_cycles =
        s_raw_isr_latest_cycles;

    const uint32_t isr_min_cycles =
        s_raw_isr_min_cycles;

    const uint32_t isr_max_cycles =
        s_raw_isr_max_cycles;

    const uint64_t isr_sum_cycles =
        s_raw_isr_sum_cycles;

    const uint32_t generation_check =
        s_raw_pps_generation;

    if (generation !=
        generation_check) {
        return;
    }

    s_processed_generation =
        generation;

    s_last_tick =
        last_tick;

    /*
     * Preserve the existing HP-visible LP edge counter.
     */
    hp_lp_pps_count =
        raw_count;

    s_isr_timing_sample_count =
        isr_timing_sample_count;

    s_isr_latest_cycles =
        isr_latest_cycles;

    s_isr_min_cycles =
        isr_min_cycles;

    s_isr_max_cycles =
        isr_max_cycles;

    s_isr_sum_cycles =
        isr_sum_cycles;

    /*
     * First PPS establishes the timestamp baseline only.
     */
    if (period_ticks == 0ULL) {
        if (hp_lp_pps_expected_ticks != 0U) {
            if (s_health ==
                HP_LP_PPS_HEALTH_LOST) {

                s_recovery_count++;
            }

            s_health =
                HP_LP_PPS_HEALTH_HEALTHY;
        }

        return;
    }

    s_period_ticks =
        period_ticks;

    s_interval_count++;

    const uint32_t expected_ticks =
        hp_lp_pps_expected_ticks;

    if (expected_ticks != 0U) {
        uint64_t error_ticks_64;

        if (period_ticks >=
            (uint64_t)expected_ticks) {

            error_ticks_64 =
                period_ticks -
                (uint64_t)expected_ticks;
        } else {
            error_ticks_64 =
                (uint64_t)expected_ticks -
                period_ticks;
        }

        if (error_ticks_64 >
            UINT32_MAX) {

            s_period_error_ticks =
                UINT32_MAX;
        } else {
            s_period_error_ticks =
                (uint32_t)error_ticks_64;
        }

        uint32_t tolerance_ticks =
            expected_ticks /
            HP_LP_PPS_TOLERANCE_DIVISOR;

        if (tolerance_ticks == 0U) {
            tolerance_ticks = 1U;
        }

        if (s_period_error_ticks <=
            tolerance_ticks) {

            s_interval_valid = 1U;
            s_valid_interval_count++;
        } else {
            s_interval_valid = 0U;
            s_invalid_interval_count++;
        }
    } else {
        s_period_error_ticks = 0U;
        s_interval_valid = 0U;
    }
}

static void hp_lp_update_watchdog(void)
{
    const uint32_t expected_ticks =
        hp_lp_pps_expected_ticks;

    const uint64_t last_tick =
        s_last_tick;

    if (expected_ticks == 0U ||
        last_tick == 0ULL) {

        s_watchdog_age_ticks = 0ULL;
        s_watchdog_timeout_ticks = 0ULL;

        s_health =
            HP_LP_PPS_HEALTH_UNKNOWN;

        return;
    }

    const uint64_t now =
        ulp_lp_core_lp_timer_get_cycle_count();

    s_watchdog_age_ticks =
        now - last_tick;

    s_watchdog_timeout_ticks =
        ((uint64_t)expected_ticks *
         HP_LP_PPS_WATCHDOG_NUMERATOR) /
        HP_LP_PPS_WATCHDOG_DENOMINATOR;

    const uint32_t previous_health =
        s_health;

    if (s_watchdog_age_ticks >
        s_watchdog_timeout_ticks) {

        if (previous_health ==
            HP_LP_PPS_HEALTH_HEALTHY) {

            s_loss_count++;
        }

        s_health =
            HP_LP_PPS_HEALTH_LOST;
    } else {
        if (previous_health ==
            HP_LP_PPS_HEALTH_LOST) {

            s_recovery_count++;
        }

        s_health =
            HP_LP_PPS_HEALTH_HEALTHY;
    }
}

void LP_CORE_ISR_ATTR
ulp_lp_core_lp_io_intr_handler(void)
{
    const uint32_t isr_entry_cycle =
        ulp_lp_core_get_cpu_cycles();

    ulp_lp_core_gpio_clear_intr_status();

    const uint64_t current_tick =
        ulp_lp_core_lp_timer_get_cycle_count();

    const uint64_t previous_tick =
        s_raw_last_pps_tick;

    s_raw_last_pps_tick =
        current_tick;

    if (previous_tick != 0ULL) {
        s_raw_period_ticks =
            current_tick -
            previous_tick;
    } else {
        s_raw_period_ticks = 0ULL;
    }

    s_raw_pps_count++;

    /*
     * Measure only the existing PPS ISR service work above.
     *
     * The timing-statistic bookkeeping below is intentionally excluded from
     * the measured interval so instrumentation does not measure itself.
     */
    const uint32_t isr_exit_cycle =
        ulp_lp_core_get_cpu_cycles();

    const uint32_t isr_cycles =
        isr_exit_cycle -
        isr_entry_cycle;

    s_raw_isr_latest_cycles =
        isr_cycles;

    if (s_raw_isr_timing_sample_count == 0U ||
        isr_cycles < s_raw_isr_min_cycles) {
        s_raw_isr_min_cycles =
            isr_cycles;
    }

    if (s_raw_isr_timing_sample_count == 0U ||
        isr_cycles > s_raw_isr_max_cycles) {
        s_raw_isr_max_cycles =
            isr_cycles;
    }

    s_raw_isr_sum_cycles +=
        (uint64_t)isr_cycles;

    s_raw_isr_timing_sample_count++;

    /*
     * Generation is published last.
     */
    s_raw_pps_generation++;
}

int main(void)
{
    lp_mailbox_t mailbox = NULL;

    hp_lp_magic =
        0x4C50434FUL;

    ulp_lp_core_intr_enable();

    ulp_lp_core_gpio_intr_enable(
        HP_LP_PPS_GPIO,
        LP_IO_INTR_POSEDGE);

    if (lp_core_mailbox_init(
            &mailbox,
            NULL) != ESP_OK) {

        while (1) {
            hp_lp_counter++;

            hp_lp_process_new_pps();
            hp_lp_update_watchdog();
            hp_lp_publish_telemetry();
        }
    }

    while (1) {
        lp_message_t command = 0;

        hp_lp_counter++;

        /*
         * Bounded mailbox receive gives the LP main loop periodic
         * execution even when HP sends no mailbox traffic.
         */
        esp_err_t err =
            lp_core_mailbox_receive(
                mailbox,
                &command,
                HP_LP_MAILBOX_POLL_CYCLES);

        if (err == ESP_OK) {
            if (command ==
                HP_LP_CMD_MAILBOX_PROOF) {

                const lp_message_t response =
                    command + 1;

                (void)lp_core_mailbox_send(
                    mailbox,
                    response,
                    -1);
            } else if (
                command ==
                HP_LP_CMD_SET_PPS_EXPECTED_TICKS) {

                lp_message_t expected_ticks = 0;

                err =
                    lp_core_mailbox_receive(
                        mailbox,
                        &expected_ticks,
                        -1);

                if (err == ESP_OK) {
                    hp_lp_pps_expected_ticks =
                        (uint32_t)expected_ticks;

                    (void)lp_core_mailbox_send(
                        mailbox,
                        expected_ticks,
                        -1);
                }
            }
        }

        /*
         * ESP_ERR_TIMEOUT is normal idle behavior.
         *
         * Watchdog operation remains independent of mailbox traffic.
         */
        hp_lp_process_new_pps();
        hp_lp_update_watchdog();
        hp_lp_publish_telemetry();
    }

    return 0;
}