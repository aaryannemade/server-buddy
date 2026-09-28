# One-shot tool: updates the C6's factory (pre-1.0) ESP-Hosted firmware to the
# image built from firmware/c6, using the legacy v2 host. Reflash firmware/p4 after.
cmake_minimum_required(VERSION 3.16)
if(NOT DEFINED ENV{SB_EXTRA_COMPONENTS})
  message(FATAL_ERROR "build via `nix build .#p4-c6-updater`")
endif()
set(EXTRA_COMPONENT_DIRS "$ENV{SB_EXTRA_COMPONENTS}")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(server_buddy_p4_c6_updater)
