#include "health.h"

#include "app_state.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "pps_service.h"

void health_get_snapshot(
    health_snapshot_t *snapshot)
{
    if (snapshot == NULL) {
        return;
    }

    uint8_t stratum = NTP_STRATUM_UNSYNCED;
    uint8_t leap = NTP_LI_UNSYNCED;

    app_state_get_ntp_status(
        &stratum,
        &leap,
        NULL,
        NULL);

    snapshot->ethernet_link_up =
        eth_service_is_link_up();

    snapshot->ipv4_ready =
        eth_service_has_ipv4();

    snapshot->gnss_valid =
        gnss_service_has_valid_time();

    snapshot->pps_present =
        pps_service_is_present();

    snapshot->time_locked =
        app_state_get_clock_state() ==
        APP_CLOCK_LOCKED;

    snapshot->ntp_stratum = stratum;
    snapshot->leap_indicator = leap;

    snapshot->valid_pps_samples =
        app_state_get_valid_pps_samples();

    snapshot->last_gnss_us =
        app_state_get_last_gnss_us();

    snapshot->last_pps_us =
        app_state_get_last_pps_us();
}

bool health_is_ready_for_ntp(void)
{
    return eth_service_has_ipv4();
}

bool health_is_ready_for_admin(void)
{
    app_clock_state_t state =
        app_state_get_clock_state();

    return state == APP_CLOCK_LOCKED ||
           state == APP_CLOCK_HOLDOVER;
}