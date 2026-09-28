idf_component_register(SRCS "main.c" "sb_eth.c" "sb_radio.c" REQUIRES sb_protocol sb_link esp_app_format esp_hosted nvs_flash esp_event esp_eth esp_netif esp_timer)
