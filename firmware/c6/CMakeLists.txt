# C6 co-processor firmware: stock ESP-Hosted v3 (from the pinned flake input).
# Phase 4 adds the ESP-NOW extension here.
cmake_minimum_required(VERSION 3.16)
if(NOT DEFINED ENV{SB_EXTRA_COMPONENTS})
  message(FATAL_ERROR "SB_EXTRA_COMPONENTS not set: build via `nix build` or inside `nix develop`")
endif()
set(EXTRA_COMPONENT_DIRS "$ENV{SB_EXTRA_COMPONENTS}")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(server_buddy_c6)
