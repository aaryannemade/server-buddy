# C6 co-processor firmware: stock ESP-Hosted v3 (from the pinned flake input).
# Adds the Server Buddy ESP-NOW radio (sb_link) on top.
cmake_minimum_required(VERSION 3.16)
if(NOT DEFINED ENV{SB_EXTRA_COMPONENTS})
  message(FATAL_ERROR "SB_EXTRA_COMPONENTS not set: build via `nix build` or inside `nix develop`")
endif()
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components" "$ENV{SB_EXTRA_COMPONENTS}")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(server_buddy_c6)
