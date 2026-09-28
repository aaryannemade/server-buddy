idf_component_register(SRCS "main.c"
                       REQUIRES esp_hosted nvs_flash esp_event esp_partition esp_app_format bootloader_support esp_rom
                       EMBED_FILES "c6_image.bin")
