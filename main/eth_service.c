#include "eth_service.h"

#include <string.h>

#include "app_config.h"
#include "app_state.h"

#include "esp_check.h"
#include "esp_eth.h"
#include "esp_eth_mac_esp.h"
#include "esp_eth_phy_ip101.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/portmacro.h"
#include "freertos/task.h"

static const char *TAG = "ETH";

#define ETH_IP_READY_BIT                         BIT0

static esp_eth_handle_t s_eth_handle;
static esp_netif_t *s_eth_netif;
static EventGroupHandle_t s_eth_events;

static portMUX_TYPE s_eth_lock = portMUX_INITIALIZER_UNLOCKED;
static eth_service_status_t s_status;

static void eth_event_handler(void *arg,
                              esp_event_base_t event_base,
                              int32_t event_id,
                              void *event_data)
{
    (void)arg;
    (void)event_base;
    (void)event_data;

    if (event_id == ETHERNET_EVENT_CONNECTED) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.link_up = true;
        portEXIT_CRITICAL(&s_eth_lock);

        ESP_LOGI(TAG, "Ethernet link up");
        return;
    }

    if (event_id == ETHERNET_EVENT_DISCONNECTED) {
        portENTER_CRITICAL(&s_eth_lock);

        s_status.link_up = false;
        s_status.ipv4_ready = false;
        s_status.ipv4_address = 0U;
        s_status.ipv4_netmask = 0U;
        s_status.ipv4_gateway = 0U;

        portEXIT_CRITICAL(&s_eth_lock);

        app_state_set_ipv4_ready(false);

        if (s_eth_events != NULL) {
            xEventGroupClearBits(s_eth_events, ETH_IP_READY_BIT);
        }

        ESP_LOGW(TAG, "Ethernet link down");
        return;
    }

    if (event_id == ETHERNET_EVENT_START) {
        ESP_LOGI(TAG, "Ethernet driver started");
        return;
    }

    if (event_id == ETHERNET_EVENT_STOP) {
        portENTER_CRITICAL(&s_eth_lock);
        s_status.started = false;
        s_status.link_up = false;
        s_status.ipv4_ready = false;
        portEXIT_CRITICAL(&s_eth_lock);

        app_state_set_ipv4_ready(false);

        if (s_eth_events != NULL) {
            xEventGroupClearBits(s_eth_events, ETH_IP_READY_BIT);
        }

        ESP_LOGW(TAG, "Ethernet driver stopped");
    }
}

static void got_ip_event_handler(void *arg,
                                 esp_event_base_t event_base,
                                 int32_t event_id,
                                 void *event_data)
{
    (void)arg;
    (void)event_base;
    (void)event_id;

    const ip_event_got_ip_t *got_ip =
        (const ip_event_got_ip_t *)event_data;

    if (got_ip == NULL) {
        return;
    }

    portENTER_CRITICAL(&s_eth_lock);

    s_status.ipv4_ready = true;
    s_status.ipv4_address = got_ip->ip_info.ip.addr;
    s_status.ipv4_netmask = got_ip->ip_info.netmask.addr;
    s_status.ipv4_gateway = got_ip->ip_info.gw.addr;

    portEXIT_CRITICAL(&s_eth_lock);

    app_state_set_ipv4_ready(true);

    if (s_eth_events != NULL) {
        xEventGroupSetBits(s_eth_events, ETH_IP_READY_BIT);
    }

    ESP_LOGI(TAG,
             "DHCP IPv4 acquired: " IPSTR,
             IP2STR(&got_ip->ip_info.ip));
}

esp_err_t eth_service_init(void)
{
    if (s_status.initialized) {
        return ESP_OK;
    }

    if (s_eth_events == NULL) {
        s_eth_events = xEventGroupCreate();

        if (s_eth_events == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    const eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();

    eth_esp32_emac_config_t emac_config =
        ETH_ESP32_EMAC_DEFAULT_CONFIG();

    emac_config.smi_gpio.mdc_num = APP_ETH_MDC_GPIO;
    emac_config.smi_gpio.mdio_num = APP_ETH_MDIO_GPIO;

    esp_eth_mac_t *mac =
        esp_eth_mac_new_esp32(&emac_config, &mac_config);

    if (mac == NULL) {
        return ESP_ERR_NO_MEM;
    }

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();

    phy_config.phy_addr = APP_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = APP_ETH_PHY_RESET_GPIO;

    esp_eth_phy_t *phy = esp_eth_phy_new_ip101(&phy_config);

    if (phy == NULL) {
        return ESP_ERR_NO_MEM;
    }

    const esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);

    ESP_RETURN_ON_ERROR(
        esp_eth_driver_install(&eth_config, &s_eth_handle),
        TAG,
        "install Ethernet driver");

    const esp_netif_config_t netif_config =
        ESP_NETIF_DEFAULT_ETH();

    s_eth_netif = esp_netif_new(&netif_config);

    if (s_eth_netif == NULL) {
        return ESP_ERR_NO_MEM;
    }

    const esp_eth_netif_glue_handle_t glue =
        esp_eth_new_netif_glue(s_eth_handle);

    if (glue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ESP_RETURN_ON_ERROR(
        esp_netif_attach(s_eth_netif, glue),
        TAG,
        "attach Ethernet netif");

    ESP_RETURN_ON_ERROR(
        esp_event_handler_register(ETH_EVENT,
                                   ESP_EVENT_ANY_ID,
                                   &eth_event_handler,
                                   NULL),
        TAG,
        "register Ethernet event handler");

    ESP_RETURN_ON_ERROR(
        esp_event_handler_register(IP_EVENT,
                                   IP_EVENT_ETH_GOT_IP,
                                   &got_ip_event_handler,
                                   NULL),
        TAG,
        "register IPv4 event handler");

    uint8_t mac_address[6] = {0};

    ESP_RETURN_ON_ERROR(
        esp_eth_ioctl(s_eth_handle,
                      ETH_CMD_G_MAC_ADDR,
                      mac_address),
        TAG,
        "read Ethernet MAC address");

    portENTER_CRITICAL(&s_eth_lock);

    memset(&s_status, 0, sizeof(s_status));

    s_status.initialized = true;
    memcpy(s_status.mac, mac_address, sizeof(s_status.mac));

    portEXIT_CRITICAL(&s_eth_lock);

    ESP_LOGI(TAG,
             "IP101 initialized: PHY=%d MDC=%d MDIO=%d RESET=%d "
             "MAC=%02x:%02x:%02x:%02x:%02x:%02x",
             APP_ETH_PHY_ADDR,
             APP_ETH_MDC_GPIO,
             APP_ETH_MDIO_GPIO,
             APP_ETH_PHY_RESET_GPIO,
             mac_address[0],
             mac_address[1],
             mac_address[2],
             mac_address[3],
             mac_address[4],
             mac_address[5]);

    return ESP_OK;
}

esp_err_t eth_service_start(void)
{
    if (!s_status.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (s_status.started) {
        return ESP_OK;
    }

    ESP_RETURN_ON_ERROR(
        esp_eth_start(s_eth_handle),
        TAG,
        "start Ethernet driver");

    portENTER_CRITICAL(&s_eth_lock);
    s_status.started = true;
    portEXIT_CRITICAL(&s_eth_lock);

    return ESP_OK;
}

void eth_service_wait_for_ip(void)
{
    if (s_eth_events == NULL) {
        ESP_LOGE(TAG, "Ethernet event group is unavailable");
        return;
    }

    while (true) {
        const EventBits_t bits = xEventGroupWaitBits(
            s_eth_events,
            ETH_IP_READY_BIT,
            pdFALSE,
            pdFALSE,
            pdMS_TO_TICKS(APP_ETH_WAIT_RETRY_MS));

        if ((bits & ETH_IP_READY_BIT) != 0U) {
            return;
        }

        ESP_LOGI(TAG, "Waiting for Ethernet DHCP IPv4 address");
        vTaskDelay(pdMS_TO_TICKS(1U));
    }
}

bool eth_service_get_status(eth_service_status_t *out_status)
{
    if (out_status == NULL) {
        return false;
    }

    portENTER_CRITICAL(&s_eth_lock);
    *out_status = s_status;
    portEXIT_CRITICAL(&s_eth_lock);

    return true;
}