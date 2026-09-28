# ESP-IDF component. Host tests build these sources directly (flake checks).
idf_component_register(
  SRCS "sb_protocol.c" "sb_describe.c" "sb_crypto.c"
  INCLUDE_DIRS "include"
  PRIV_REQUIRES mbedtls)
