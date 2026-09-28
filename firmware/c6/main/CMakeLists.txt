idf_component_register(SRCS "main.c"
                       REQUIRES esp_hosted sb_link
                       PRIV_REQUIRES nvs_flash esp_event esp_wifi esp_timer)
