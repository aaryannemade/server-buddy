// Onboard IP101 Ethernet (P4 EMAC, RMII, external 50 MHz ref clock on GPIO50).
// Pins are ESP-IDF's P4 defaults, which Waveshare's 11_ethernetbasic uses.
#include "sb_eth.h"

#include "esp_check.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"

#define PHY_ADDR 1
#define PHY_RST_GPIO 51
#define MDC_GPIO 31
#define MDIO_GPIO 52

static const char *TAG = "sb_eth";
static esp_netif_t *s_netif;
static volatile bool s_has_ip;
static sb_eth_stats_t s_stats;
static int64_t s_down_at_us, s_down_ip_us;

static void on_eth(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    esp_eth_handle_t h = *(esp_eth_handle_t *)data;
    switch (id) {
    case ETHERNET_EVENT_CONNECTED: {
        eth_speed_t speed;
        eth_duplex_t duplex;
        esp_eth_ioctl(h, ETH_CMD_G_SPEED, &speed);
        esp_eth_ioctl(h, ETH_CMD_G_DUPLEX_MODE, &duplex);
        s_stats.link_up = true;
        s_stats.link_ups++;
        if (s_down_at_us) {
            s_stats.last_down_ms = (uint32_t)((esp_timer_get_time() - s_down_at_us) / 1000);
            s_down_at_us = 0;
        }
        ESP_LOGI(TAG, "link up #%" PRIu32 ": %s Mbps %s duplex (was down %" PRIu32 " ms)",
                 s_stats.link_ups, speed == ETH_SPEED_100M ? "100" : "10",
                 duplex == ETH_DUPLEX_FULL ? "full" : "half", s_stats.last_down_ms);
        break;
    }
    case ETHERNET_EVENT_DISCONNECTED:
        s_has_ip = false;
        s_stats.link_up = false;
        s_stats.link_downs++;
        s_down_at_us = s_down_ip_us = esp_timer_get_time();
        ESP_LOGW(TAG, "link down #%" PRIu32, s_stats.link_downs);
        break;
    default:
        break;
    }
}

static void on_ip(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (id == IP_EVENT_ETH_GOT_IP) {
        const ip_event_got_ip_t *e = data;
        s_has_ip = true;
        s_stats.ip_acquired++;
        s_stats.ip = e->ip_info.ip.addr;
        uint32_t since_down = s_down_ip_us ? (uint32_t)((esp_timer_get_time() - s_down_ip_us) / 1000) : 0;
        s_down_ip_us = 0;
        ESP_LOGI(TAG, "got IP " IPSTR " mask " IPSTR " gw " IPSTR " (#%" PRIu32 ", %" PRIu32 " ms after link loss)",
                 IP2STR(&e->ip_info.ip), IP2STR(&e->ip_info.netmask), IP2STR(&e->ip_info.gw),
                 s_stats.ip_acquired, since_down);
    } else if (id == IP_EVENT_ETH_LOST_IP) {
        s_has_ip = false;
        ESP_LOGW(TAG, "lost IP");
    }
}

esp_err_t sb_eth_start(const char *hostname)
{
    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "netif init");
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    s_netif = esp_netif_new(&cfg);
    if (!s_netif) return ESP_FAIL;
    esp_netif_set_hostname(s_netif, hostname);

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac_cfg.smi_gpio.mdc_num = MDC_GPIO;
    emac_cfg.smi_gpio.mdio_num = MDIO_GPIO;
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_cfg, &mac_cfg);

    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr = PHY_ADDR;
    phy_cfg.reset_gpio_num = PHY_RST_GPIO;
    esp_eth_phy_t *phy = esp_eth_phy_new_ip101(&phy_cfg);
    if (!mac || !phy) return ESP_FAIL;

    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth = NULL;
    ESP_RETURN_ON_ERROR(esp_eth_driver_install(&eth_cfg, &eth), TAG, "driver install");

    uint8_t mac_addr[6];
    ESP_RETURN_ON_ERROR(esp_read_mac(mac_addr, ESP_MAC_ETH), TAG, "read mac");
    ESP_LOGI(TAG, "MAC " MACSTR ", hostname %s", MAC2STR(mac_addr), hostname);

    ESP_RETURN_ON_ERROR(esp_netif_attach(s_netif, esp_eth_new_netif_glue(eth)), TAG, "attach");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, on_eth, NULL),
                        TAG, "eth events");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, on_ip, NULL), TAG,
                        "ip events");
    return esp_eth_start(eth);
}

bool sb_eth_has_ip(void) { return s_has_ip; }

sb_eth_stats_t sb_eth_stats(void) { return s_stats; }
