#include "web_console.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "app_state.h"
#include "clock_discipline.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "ntp_server.h"
#include "ntp_types.h"
#include "pps_service.h"

#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_netif.h"

static const char *TAG = "WEB";

#define APP_WEB_CONSOLE_PORT                    443U
#define APP_WEB_CONSOLE_STACK_SIZE              8192U
#define APP_WEB_CONSOLE_MAX_HANDLERS            8U
#define APP_WEB_CONSOLE_MAX_OPEN_SOCKETS        4U

static httpd_handle_t s_server;
static bool s_started;

extern const unsigned char servercert_pem_start[] asm("_binary_servercert_pem_start");
extern const unsigned char servercert_pem_end[] asm("_binary_servercert_pem_end");
extern const unsigned char serverkey_pem_start[] asm("_binary_serverkey_pem_start");
extern const unsigned char serverkey_pem_end[] asm("_binary_serverkey_pem_end");

static const char *clock_state_to_string(app_clock_state_t state)
{
    switch (state) {
    case APP_CLOCK_UNSYNCHRONIZED:
        return "UNSYNCHRONIZED";

    case APP_CLOCK_ACQUIRING:
        return "ACQUIRING";

    case APP_CLOCK_SYNCHRONIZED:
        return "SYNCHRONIZED";

    case APP_CLOCK_HOLDOVER:
        return "HOLDOVER";

    case APP_CLOCK_FAIL_CLOSED:
        return "FAIL_CLOSED";

    default:
        return "UNKNOWN";
    }
}

static const char *leap_to_string(app_leap_indicator_t leap)
{
    switch (leap) {
    case APP_LEAP_NO_WARNING:
        return "NONE";

    case APP_LEAP_ADD_SECOND:
        return "ADD_SECOND";

    case APP_LEAP_DELETE_SECOND:
        return "DELETE_SECOND";

    case APP_LEAP_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static bool clock_is_servable(app_clock_state_t state,
                              bool solution_valid)
{
    return solution_valid &&
           (state == APP_CLOCK_SYNCHRONIZED ||
            state == APP_CLOCK_HOLDOVER);
}

static bool get_current_unix_time(int64_t *out_unix_time)
{
    if (out_unix_time == NULL) {
        return false;
    }

    clock_ntp_timestamp_t ntp_time;

    if (!clock_discipline_get_ntp_timestamp(&ntp_time)) {
        return false;
    }

    if (ntp_time.seconds < APP_NTP_EPOCH_DELTA) {
        return false;
    }

    *out_unix_time =
        (int64_t)ntp_time.seconds -
        (int64_t)APP_NTP_EPOCH_DELTA;

    return true;
}

static void set_security_headers(httpd_req_t *request)
{
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(request, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(request, "Referrer-Policy", "no-referrer");
}

static esp_err_t send_status_json(httpd_req_t *request)
{
    app_state_snapshot_t app_status;
    clock_discipline_status_t clock_status;
    gnss_service_status_t gnss_status;
    pps_service_status_t pps_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;

    (void)app_state_get_snapshot(&app_status);
    (void)clock_discipline_get_status(&clock_status);
    (void)gnss_service_get_status(&gnss_status);
    (void)pps_service_get_status(&pps_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);

    const esp_ip4_addr_t device_ip = {
        .addr = eth_status.ipv4_address,
    };

    const esp_ip4_addr_t netmask = {
        .addr = eth_status.ipv4_netmask,
    };

    const esp_ip4_addr_t gateway = {
        .addr = eth_status.ipv4_gateway,
    };

    const esp_ip4_addr_t last_client = {
        .addr = ntp_status.last_client_ipv4,
    };

    int64_t unix_now = 0;

    const bool current_time_valid =
        get_current_unix_time(&unix_now);

    const bool ntp_ready =
        eth_status.ipv4_ready &&
        ntp_status.socket_bound &&
        clock_is_servable(clock_status.state,
                          clock_status.solution_valid);

    char response[4096];

    const int length = snprintf(
        response,
        sizeof(response),
        "{"
        "\"console\":{"
        "\"mode\":\"read_only_https\","
        "\"port\":%u"
        "},"
        "\"readiness\":{"
        "\"ntp_ready\":%s,"
        "\"clock_now_valid\":%s,"
        "\"unix_time\":%" PRId64
        "},"
        "\"device\":{"
        "\"hostname\":\"%s\","
        "\"ipv4_ready\":%s,"
        "\"ipv4\":\"" IPSTR "\","
        "\"netmask\":\"" IPSTR "\","
        "\"gateway\":\"" IPSTR "\","
        "\"link_up\":%s,"
        "\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\""
        "},"
        "\"clock\":{"
        "\"state\":\"%s\","
        "\"solution_valid\":%s,"
        "\"phase_error_ns\":%" PRId64 ","
        "\"frequency_ppm\":%.6f,"
        "\"accepted_samples\":%" PRIu32 ","
        "\"rejected_samples\":%" PRIu32 ","
        "\"holdover_seconds\":%" PRIu32 ","
        "\"root_dispersion_16_16\":%" PRIu32
        "},"
        "\"gnss\":{"
        "\"utc_valid\":%s,"
        "\"utc_seconds\":%" PRId64 ","
        "\"fix_valid\":%s,"
        "\"fix_type\":%u,"
        "\"satellites\":%u,"
        "\"fully_resolved\":%s,"
        "\"leap\":\"%s\","
        "\"current_leap_seconds\":%d,"
        "\"pending_leap_change\":%d,"
        "\"seconds_to_leap_event\":%" PRId32 ","
        "\"timing_pulse_valid\":%s,"
        "\"timing_week\":%u,"
        "\"timing_tow_ms\":%" PRIu32 ","
        "\"timing_qerr_ps\":%" PRId32
        "},"
        "\"pps\":{"
        "\"valid\":%s,"
        "\"period_us\":%" PRIu32 ","
        "\"jitter_us\":%" PRIu32 ","
        "\"age_us\":%" PRId64 ","
        "\"edge_count\":%" PRIu32 ","
        "\"queue_drops\":%" PRIu32
        "},"
        "\"ntp\":{"
        "\"started\":%s,"
        "\"socket_bound\":%s,"
        "\"requests\":%" PRIu32 ","
        "\"responses\":%" PRIu32 ","
        "\"invalid_requests\":%" PRIu32 ","
        "\"unsynchronized_drops\":%" PRIu32 ","
        "\"rate_kod\":%" PRIu32 ","
        "\"send_failures\":%" PRIu32 ","
        "\"socket_failures\":%" PRIu32 ","
        "\"advertised_stratum\":%u,"
        "\"advertised_leap\":%u,"
        "\"root_dispersion_16_16\":%" PRIu32 ","
        "\"last_client\":\"" IPSTR "\","
        "\"last_request_monotonic_us\":%" PRId64 ","
        "\"last_response_monotonic_us\":%" PRId64
        "}"
        "}",
        APP_WEB_CONSOLE_PORT,
        ntp_ready ? "true" : "false",
        current_time_valid ? "true" : "false",
        unix_now,

        app_status.device_hostname,
        eth_status.ipv4_ready ? "true" : "false",
        IP2STR(&device_ip),
        IP2STR(&netmask),
        IP2STR(&gateway),
        eth_status.link_up ? "true" : "false",
        eth_status.mac[0],
        eth_status.mac[1],
        eth_status.mac[2],
        eth_status.mac[3],
        eth_status.mac[4],
        eth_status.mac[5],

        clock_state_to_string(clock_status.state),
        clock_status.solution_valid ? "true" : "false",
        clock_status.phase_error_ns,
        clock_status.frequency_ppm,
        clock_status.accepted_samples,
        clock_status.rejected_samples,
        clock_status.holdover_seconds,
        clock_status.root_dispersion_16_16,

        gnss_status.utc_valid ? "true" : "false",
        gnss_status.utc_seconds,
        gnss_status.gnss_fix_valid ? "true" : "false",
        gnss_status.fix_type,
        gnss_status.satellites_used,
        gnss_status.gnss_time_fully_resolved ? "true" : "false",
        leap_to_string(gnss_status.leap_indicator),
        gnss_status.current_leap_seconds,
        gnss_status.pending_leap_change,
        gnss_status.seconds_to_leap_event,
        gnss_status.timing_pulse_valid ? "true" : "false",
        gnss_status.timing_week,
        gnss_status.timing_tow_ms,
        gnss_status.timing_quantization_error_ns,

        pps_status.interval_valid ? "true" : "false",
        pps_status.period_us,
        pps_status.jitter_us,
        pps_status.age_us,
        pps_status.edge_count,
        pps_status.queue_drops,

        ntp_status.started ? "true" : "false",
        ntp_status.socket_bound ? "true" : "false",
        ntp_status.requests_received,
        ntp_status.normal_responses,
        ntp_status.invalid_requests,
        ntp_status.unsynchronized_drops,
        ntp_status.rate_kod_responses,
        ntp_status.send_failures,
        ntp_status.socket_open_failures,
        ntp_status.advertised_stratum,
        ntp_status.advertised_leap_indicator,
        ntp_status.advertised_root_dispersion,
        IP2STR(&last_client),
        ntp_status.last_request_monotonic_us,
        ntp_status.last_response_monotonic_us);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "status serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);

    return httpd_resp_send(request,
                           response,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_health_response(httpd_req_t *request)
{
    clock_discipline_status_t clock_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;

    (void)clock_discipline_get_status(&clock_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);

    const bool healthy =
        eth_status.ipv4_ready &&
        eth_status.link_up &&
        ntp_status.socket_bound &&
        clock_is_servable(clock_status.state,
                          clock_status.solution_valid);

    app_state_snapshot_t app_status;
    (void)app_state_get_snapshot(&app_status);

    char response[256];
    const int length = snprintf(
        response,
        sizeof(response),
        "{\"status\":\"%s\",\"hostname\":\"%s\",\"ntp_ready\":%s}\n",
        healthy ? "ok" : "not-ready",
        app_status.device_hostname,
        healthy ? "true" : "false");

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "health serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);

    httpd_resp_set_status(request,
                          healthy ? "200 OK" : "503 Service Unavailable");

    return httpd_resp_send(request,
                           response,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_metrics_response(httpd_req_t *request)
{
    clock_discipline_status_t clock_status;
    gnss_service_status_t gnss_status;
    pps_service_status_t pps_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;

    (void)clock_discipline_get_status(&clock_status);
    (void)gnss_service_get_status(&gnss_status);
    (void)pps_service_get_status(&pps_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);

    char response[3072];

    const int length = snprintf(
        response,
        sizeof(response),
        "# HELP esp32_ntp_clock_state Clock state enumeration.\n"
        "# TYPE esp32_ntp_clock_state gauge\n"
        "esp32_ntp_clock_state %d\n"
        "# HELP esp32_ntp_clock_solution_valid Clock validity.\n"
        "# TYPE esp32_ntp_clock_solution_valid gauge\n"
        "esp32_ntp_clock_solution_valid %d\n"
        "# HELP esp32_ntp_clock_phase_error_ns Clock phase error.\n"
        "# TYPE esp32_ntp_clock_phase_error_ns gauge\n"
        "esp32_ntp_clock_phase_error_ns %" PRId64 "\n"
        "# HELP esp32_ntp_clock_frequency_ppm Clock frequency estimate.\n"
        "# TYPE esp32_ntp_clock_frequency_ppm gauge\n"
        "esp32_ntp_clock_frequency_ppm %.6f\n"
        "# HELP esp32_ntp_clock_holdover_seconds Holdover duration.\n"
        "# TYPE esp32_ntp_clock_holdover_seconds gauge\n"
        "esp32_ntp_clock_holdover_seconds %" PRIu32 "\n"
        "# HELP esp32_ntp_gnss_utc_valid GNSS UTC validity.\n"
        "# TYPE esp32_ntp_gnss_utc_valid gauge\n"
        "esp32_ntp_gnss_utc_valid %d\n"
        "# HELP esp32_ntp_gnss_satellites Satellites used.\n"
        "# TYPE esp32_ntp_gnss_satellites gauge\n"
        "esp32_ntp_gnss_satellites %u\n"
        "# HELP esp32_ntp_pps_valid PPS validity.\n"
        "# TYPE esp32_ntp_pps_valid gauge\n"
        "esp32_ntp_pps_valid %d\n"
        "# HELP esp32_ntp_pps_jitter_us PPS jitter.\n"
        "# TYPE esp32_ntp_pps_jitter_us gauge\n"
        "esp32_ntp_pps_jitter_us %" PRIu32 "\n"
        "# HELP esp32_ntp_ethernet_ipv4_ready Ethernet IPv4 readiness.\n"
        "# TYPE esp32_ntp_ethernet_ipv4_ready gauge\n"
        "esp32_ntp_ethernet_ipv4_ready %d\n"
        "# HELP esp32_ntp_server_socket_bound NTP UDP socket state.\n"
        "# TYPE esp32_ntp_server_socket_bound gauge\n"
        "esp32_ntp_server_socket_bound %d\n"
        "# HELP esp32_ntp_server_requests_total NTP requests.\n"
        "# TYPE esp32_ntp_server_requests_total counter\n"
        "esp32_ntp_server_requests_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_responses_total NTP responses.\n"
        "# TYPE esp32_ntp_server_responses_total counter\n"
        "esp32_ntp_server_responses_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_rate_kod_total RATE KoD responses.\n"
        "# TYPE esp32_ntp_server_rate_kod_total counter\n"
        "esp32_ntp_server_rate_kod_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_unsynchronized_drops_total "
        "Fail-closed NTP drops.\n"
        "# TYPE esp32_ntp_server_unsynchronized_drops_total counter\n"
        "esp32_ntp_server_unsynchronized_drops_total %" PRIu32 "\n",
        (int)clock_status.state,
        clock_status.solution_valid ? 1 : 0,
        clock_status.phase_error_ns,
        clock_status.frequency_ppm,
        clock_status.holdover_seconds,
        gnss_status.utc_valid ? 1 : 0,
        gnss_status.satellites_used,
        pps_status.interval_valid ? 1 : 0,
        pps_status.jitter_us,
        eth_status.ipv4_ready ? 1 : 0,
        ntp_status.socket_bound ? 1 : 0,
        ntp_status.requests_received,
        ntp_status.normal_responses,
        ntp_status.rate_kod_responses,
        ntp_status.unsynchronized_drops);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "metrics serialization failed");
    }

    httpd_resp_set_type(request,
                        "text/plain; version=0.0.4; charset=utf-8");
    set_security_headers(request);

    return httpd_resp_send(request,
                           response,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t index_handler(httpd_req_t *request)
{
    static const char html[] =
        "<!doctype html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>ESP32-P4 NTP Console</title>"
        "<style>"
        ":root{color-scheme:dark}"
        "body{margin:0;background:#0d141b;color:#e9f0f5;"
        "font-family:Arial,sans-serif}"
        "header{padding:22px 28px;background:#14212d;border-bottom:1px solid #294252}"
        "h1{margin:0;color:#58c7ff;font-size:1.55rem}"
        "header p{margin:7px 0 0;color:#a8bac7;font-size:.92rem}"
        "main{padding:22px;max-width:1320px;margin:auto}"
        ".summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}"
        ".badge{padding:8px 12px;border-radius:999px;font-weight:bold;font-size:.82rem}"
        ".ok{background:#173f2b;color:#9bea75}"
        ".warn{background:#493b18;color:#ffd569}"
        ".bad{background:#4c2226;color:#ff9292}"
        ".neutral{background:#223643;color:#a9d8ef}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}"
        ".card{background:#14212d;border:1px solid #294252;border-radius:10px;"
        "padding:18px;min-width:0}"
        ".card h2{margin:0 0 14px;color:#8fdb75;font-size:1.02rem}"
        ".row{display:grid;grid-template-columns:minmax(135px,1fr) minmax(145px,auto);"
        "column-gap:30px;row-gap:7px;padding:10px 0;"
        "border-bottom:1px solid #203440;align-items:center}"
        ".row:last-child{border-bottom:0}"
        ".key{color:#9eb2c0;line-height:1.4}"
        ".value{font-family:ui-monospace,Consolas,monospace;text-align:right;"
        "line-height:1.4;overflow-wrap:anywhere}"
        "footer{padding:22px 0 4px;color:#8ca1ae;font-size:.82rem}"
        "code{color:#9bea75}"
        "</style>"
        "</head>"
        "<body>"
        "<header>"
        "<h1>ESP32-P4 GNSS NTP Server</h1>"
        "<p>Read-only HTTPS operational console &middot; automatic refresh every three seconds</p>"
        "</header>"
        "<main>"
        "<div class=\"summary\" id=\"summary\"></div>"
        "<div class=\"grid\" id=\"cards\"></div>"
        "<footer>"
        "Read-only HTTPS endpoints: <code>/api/v1/status</code> &middot; "
        "<code>/api/v1/health</code> &middot; <code>/metrics</code>"
        "</footer>"
        "</main>"
        "<script>"
        "function esc(v){return String(v == null ? '--' : v).replace(/[&<>\"']/g,"
        "c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}"
        "function row(k,v){return '<div class=\"row\"><span class=\"key\">'+esc(k)+"
        "'</span><span class=\"value\">'+esc(v)+'</span></div>';}"
        "function card(t,r){return '<section class=\"card\"><h2>'+esc(t)+"
        "'</h2>'+r.join('')+'</section>';}"
        "function badge(t,c){return '<span class=\"badge '+c+'\">'+esc(t)+'</span>';}"
        "function stateClass(s){if(s==='SYNCHRONIZED')return 'ok';"
        "if(s==='HOLDOVER'||s==='ACQUIRING')return 'warn';return 'bad';}"
        "function yesNo(v){return v?'YES':'NO';}"
        "function utc(v,valid){if(!valid)return '--';"
        "return new Date(Number(v)*1000).toISOString();}"
        "async function refresh(){"
        "try{"
        "const r=await fetch('/api/v1/status',{cache:'no-store'});"
        "if(!r.ok)throw new Error('status unavailable');"
        "const d=await r.json();"
        "const summary=[];"
        "summary.push(badge('Clock: '+d.clock.state,stateClass(d.clock.state)));"
        "summary.push(badge('NTP: '+(d.readiness.ntp_ready?'READY':'NOT READY'),"
        "d.readiness.ntp_ready?'ok':'bad'));"
        "summary.push(badge('GNSS UTC: '+yesNo(d.gnss.utc_valid),"
        "d.gnss.utc_valid?'ok':'bad'));"
        "summary.push(badge('PPS: '+yesNo(d.pps.valid),"
        "d.pps.valid?'ok':'bad'));"
        "summary.push(badge('Ethernet: '+yesNo(d.device.ipv4_ready),"
        "d.device.ipv4_ready?'ok':'bad'));"
        "document.getElementById('summary').innerHTML=summary.join('');"
        "const c=[];"
        "c.push(card('Clock and Time',["
        "row('State',d.clock.state),"
        "row('Disciplined',yesNo(d.clock.solution_valid)),"
        "row('UTC Time',utc(d.readiness.unix_time,d.readiness.clock_now_valid)),"
        "row('Phase Error',d.clock.phase_error_ns+' ns'),"
        "row('Frequency',d.clock.frequency_ppm+' ppm'),"
        "row('Samples',d.clock.accepted_samples+' accepted / '+d.clock.rejected_samples+' rejected'),"
        "row('Holdover',d.clock.holdover_seconds+' s'),"
        "row('Root Dispersion','0x'+Number(d.clock.root_dispersion_16_16).toString(16))"
        "]));"
        "c.push(card('GNSS Receiver',["
        "row('UTC Valid',yesNo(d.gnss.utc_valid)),"
        "row('Fix Valid',yesNo(d.gnss.fix_valid)),"
        "row('Fix Type',d.gnss.fix_type),"
        "row('Satellites',d.gnss.satellites),"
        "row('Time Fully Resolved',yesNo(d.gnss.fully_resolved)),"
        "row('Leap State',d.gnss.leap),"
        "row('Current Leap Offset',d.gnss.current_leap_seconds+' s'),"
        "row('TIM-TP qErr',d.gnss.timing_qerr_ps+' ps')"
        "]));"
        "c.push(card('PPS Capture',["
        "row('Interval Valid',yesNo(d.pps.valid)),"
        "row('Period',d.pps.period_us+' us'),"
        "row('Jitter',d.pps.jitter_us+' us'),"
        "row('Last Edge Age',d.pps.age_us+' us'),"
        "row('Captured Edges',d.pps.edge_count),"
        "row('Queue Drops',d.pps.queue_drops)"
        "]));"
        "c.push(card('Network',["
        "row('Hostname',d.device.hostname),"
        "row('IPv4 Address',d.device.ipv4),"
        "row('Netmask',d.device.netmask),"
        "row('Gateway',d.device.gateway),"
        "row('Ethernet Link',yesNo(d.device.link_up)),"
        "row('Ethernet MAC',d.device.mac),"
        "row('Console Mode',d.console.mode)"
        "]));"
        "c.push(card('NTP Service',["
        "row('UDP Socket Bound',yesNo(d.ntp.socket_bound)),"
        "row('Advertised Stratum',d.ntp.advertised_stratum),"
        "row('Requests Received',d.ntp.requests),"
        "row('Responses Sent',d.ntp.responses),"
        "row('Invalid Requests',d.ntp.invalid_requests),"
        "row('Fail-Closed Drops',d.ntp.unsynchronized_drops),"
        "row('RATE KoD Responses',d.ntp.rate_kod),"
        "row('Last Client',d.ntp.last_client)"
        "]));"
        "document.getElementById('cards').innerHTML=c.join('');"
        "}catch(e){"
        "document.getElementById('summary').innerHTML=badge('Console: STATUS UNAVAILABLE','bad');"
        "document.getElementById('cards').innerHTML="
        "'<section class=\"card\"><h2>Console Error</h2><p>Unable to retrieve device status.</p></section>';"
        "}"
        "}"
        "refresh();setInterval(refresh,3000);"
        "</script>"
        "</body>"
        "</html>";

    httpd_resp_set_type(request, "text/html");
    set_security_headers(request);

    return httpd_resp_send(request,
                           html,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t status_handler(httpd_req_t *request)
{
    return send_status_json(request);
}

static esp_err_t health_handler(httpd_req_t *request)
{
    return send_health_response(request);
}

static esp_err_t metrics_handler(httpd_req_t *request)
{
    return send_metrics_response(request);
}

static const httpd_uri_t s_index_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = index_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_status_uri = {
    .uri = "/api/v1/status",
    .method = HTTP_GET,
    .handler = status_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_health_uri = {
    .uri = "/api/v1/health",
    .method = HTTP_GET,
    .handler = health_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_metrics_uri = {
    .uri = "/metrics",
    .method = HTTP_GET,
    .handler = metrics_handler,
    .user_ctx = NULL,
};

esp_err_t web_console_start(void)
{
    if (s_started) {
        return ESP_OK;
    }

    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();

    config.httpd.stack_size = APP_WEB_CONSOLE_STACK_SIZE;
    config.httpd.max_uri_handlers = APP_WEB_CONSOLE_MAX_HANDLERS;
    config.httpd.max_open_sockets = APP_WEB_CONSOLE_MAX_OPEN_SOCKETS;
    config.httpd.lru_purge_enable = true;
    config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    config.port_secure = APP_WEB_CONSOLE_PORT;
    config.servercert = servercert_pem_start;
    config.servercert_len = (size_t)(servercert_pem_end - servercert_pem_start);
    config.prvtkey_pem = serverkey_pem_start;
    config.prvtkey_len = (size_t)(serverkey_pem_end - serverkey_pem_start);

    esp_err_t err = httpd_ssl_start(&s_server, &config);

    if (err != ESP_OK) {
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_index_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_status_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_health_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    err = httpd_register_uri_handler(s_server, &s_metrics_uri);

    if (err != ESP_OK) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        return err;
    }

    s_started = true;

    ESP_LOGW(TAG,
             "Read-only HTTPS console active on TCP/%u; "
             "restrict access to a trusted management network",
             APP_WEB_CONSOLE_PORT);

    return ESP_OK;
}

bool web_console_is_running(void)
{
    return s_started;
}