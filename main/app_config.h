#pragma once

/* --------------------------------------------------------------------------
 * Ethernet
 * -------------------------------------------------------------------------- */

#ifndef CONFIG_APP_ETH_PHY_ADDR
#define CONFIG_APP_ETH_PHY_ADDR                 1
#endif

#ifndef CONFIG_APP_ETH_MDC_GPIO
#define CONFIG_APP_ETH_MDC_GPIO                 31
#endif

#ifndef CONFIG_APP_ETH_MDIO_GPIO
#define CONFIG_APP_ETH_MDIO_GPIO                52
#endif

#ifndef CONFIG_APP_ETH_PHY_RESET_GPIO
#define CONFIG_APP_ETH_PHY_RESET_GPIO           51
#endif

#define APP_ETH_PHY_ADDR                        CONFIG_APP_ETH_PHY_ADDR
#define APP_ETH_MDC_GPIO                        CONFIG_APP_ETH_MDC_GPIO
#define APP_ETH_MDIO_GPIO                       CONFIG_APP_ETH_MDIO_GPIO
#define APP_ETH_PHY_RESET_GPIO                  CONFIG_APP_ETH_PHY_RESET_GPIO

/* --------------------------------------------------------------------------
 * GNSS and PPS hardware
 * -------------------------------------------------------------------------- */

#ifndef CONFIG_APP_PPS_GPIO
#define CONFIG_APP_PPS_GPIO                     5
#endif

#ifndef CONFIG_APP_GNSS_UART_NUM
#define CONFIG_APP_GNSS_UART_NUM                1
#endif

#ifndef CONFIG_APP_GNSS_UART_RX_GPIO
#define CONFIG_APP_GNSS_UART_RX_GPIO            2
#endif

#ifndef CONFIG_APP_GNSS_UART_TX_GPIO
#define CONFIG_APP_GNSS_UART_TX_GPIO            3
#endif

#ifndef CONFIG_APP_GNSS_UART_BAUD
#define CONFIG_APP_GNSS_UART_BAUD               115200
#endif

#ifndef CONFIG_APP_GNSS_CONFIGURE_UBX_ON_BOOT
#define CONFIG_APP_GNSS_CONFIGURE_UBX_ON_BOOT   1
#endif

#ifndef CONFIG_APP_GNSS_CONFIGURE_TIMEPULSE
#define CONFIG_APP_GNSS_CONFIGURE_TIMEPULSE     0
#endif

#ifndef CONFIG_APP_GNSS_TIMEOUT_SECONDS
#define CONFIG_APP_GNSS_TIMEOUT_SECONDS         5
#endif

#define APP_PPS_GPIO                            CONFIG_APP_PPS_GPIO

#define APP_GNSS_UART_NUM                       CONFIG_APP_GNSS_UART_NUM
#define APP_GNSS_UART_RX_GPIO                   CONFIG_APP_GNSS_UART_RX_GPIO
#define APP_GNSS_UART_TX_GPIO                   CONFIG_APP_GNSS_UART_TX_GPIO
#define APP_GNSS_UART_BAUD                      CONFIG_APP_GNSS_UART_BAUD
#define APP_GNSS_CONFIGURE_UBX_ON_BOOT          CONFIG_APP_GNSS_CONFIGURE_UBX_ON_BOOT
#define APP_GNSS_CONFIGURE_TIMEPULSE            CONFIG_APP_GNSS_CONFIGURE_TIMEPULSE
#define APP_GNSS_TIMEOUT_SECONDS                CONFIG_APP_GNSS_TIMEOUT_SECONDS

/* --------------------------------------------------------------------------
 * Clock quality and holdover
 * -------------------------------------------------------------------------- */

#ifndef CONFIG_APP_CLOCK_LOCK_SAMPLES
#define CONFIG_APP_CLOCK_LOCK_SAMPLES           8
#endif

#ifndef CONFIG_APP_HOLDOVER_MAX_SECONDS
#define CONFIG_APP_HOLDOVER_MAX_SECONDS         300
#endif

#ifndef CONFIG_APP_PPS_TIMEOUT_MS
#define CONFIG_APP_PPS_TIMEOUT_MS               2500
#endif

#define APP_CLOCK_LOCK_SAMPLES                  CONFIG_APP_CLOCK_LOCK_SAMPLES
#define APP_HOLDOVER_MAX_SECONDS                CONFIG_APP_HOLDOVER_MAX_SECONDS
#define APP_PPS_TIMEOUT_MS                      CONFIG_APP_PPS_TIMEOUT_MS

#define APP_PPS_TIMER_RESOLUTION_HZ             1000000U
#define APP_PPS_NOMINAL_INTERVAL_US             1000000ULL
#define APP_PPS_MIN_INTERVAL_US                 800000ULL
#define APP_PPS_MAX_INTERVAL_US                 1200000ULL

#define APP_CLOCK_MAX_PPS_JITTER_US             250U
#define APP_CLOCK_MAX_TIMING_QERR_NS            50000
#define APP_CLOCK_MAX_CONSECUTIVE_REJECTS       3U

#define APP_CLOCK_BASE_DISPERSION_NS            100000LL
#define APP_CLOCK_HOLDOVER_WANDER_PPM           20.0
#define APP_CLOCK_MAX_HOLDOVER_DISPERSION_NS    1000000000LL

#define APP_CLOCK_MAX_ACCEPTABLE_ERROR_NS       250000000LL
#define APP_CLOCK_MAX_FREQUENCY_PPM             200.0
#define APP_CLOCK_FREQUENCY_FILTER_GAIN         0.125
#define APP_CLOCK_PHASE_FILTER_GAIN             0.125

/* --------------------------------------------------------------------------
 * Task and buffer configuration
 * -------------------------------------------------------------------------- */

#define APP_PPS_EVENT_QUEUE_LENGTH              16U
#define APP_PPS_TASK_STACK_SIZE                 4096U
#define APP_PPS_TASK_PRIORITY                   16U

#define APP_GNSS_TASK_STACK_SIZE                6144U
#define APP_GNSS_TASK_PRIORITY                  14U
#define APP_GNSS_UART_RX_BUFFER_SIZE            4096U
#define APP_GNSS_UART_TX_BUFFER_SIZE            1024U
#define APP_GNSS_UBX_ACK_TIMEOUT_MS             1200U
#define APP_GNSS_UBX_COMMAND_RETRIES            2U
#define APP_GNSS_UBX_MAX_PAYLOAD_LENGTH         128U
#define APP_GNSS_TP1_FREQUENCY_HZ               1U
#define APP_GNSS_TP1_PULSE_LENGTH_US            100000U

#define APP_CLOCK_TASK_STACK_SIZE               4096U
#define APP_CLOCK_TASK_PRIORITY                 15U

#define APP_DIAGNOSTICS_TASK_STACK_SIZE         3072U
#define APP_DIAGNOSTICS_TASK_PRIORITY           5U

#define APP_ETH_WAIT_RETRY_MS                   1000U

#define APP_NTP_EPOCH_DELTA                     2208988800ULL