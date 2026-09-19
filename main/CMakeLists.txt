idf_component_register(
    SRCS
        "app_main.c"
        "app_state.c"
        "device_config.c"
        "cloudflare_client.c"
        "acme_client.c"
        "acme_storage.c"
        "pps_service.c"
        "gnss_service.c"
        "clock_discipline.c"
        "diagnostics.c"
        "eth_service.c"
        "ntp_packet.c"
        "ntp_rate_limit.c"
        "ntp_server.c"
        "web_console.c"
        "hp_lp_test.c"

    INCLUDE_DIRS
        "."

    REQUIRES
        esp_eth
        esp_event
        esp_netif
        esp_timer
        esp_http_server
        esp_https_server
        esp_http_client
        mbedtls
        esp_driver_gpio
        esp_driver_gptimer
        esp_driver_uart
        esp_hw_support
        nvs_flash
        bootloader_support
        freertos
        lwip
        log
        espressif__ip101
        ulp

    EMBED_TXTFILES
        "servercert.pem"
        "serverkey.pem"
        "management_ca.pem"
)

set(ulp_app_name ulp_hp_lp_test)

set(ulp_sources
    "ulp/hp_lp_test_lp.c"
)

set(ulp_exp_dep_srcs
    "hp_lp_test.c"
)

ulp_embed_binary(
    ${ulp_app_name}
    "${ulp_sources}"
    "${ulp_exp_dep_srcs}"
)