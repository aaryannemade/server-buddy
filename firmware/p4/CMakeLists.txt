cmake_minimum_required(VERSION 3.16)

# Shared components plus pinned third-party ones (esp_hosted) supplied by the
# flake via SB_EXTRA_COMPONENTS; builds never use the online component manager.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components")
if(DEFINED ENV{SB_EXTRA_COMPONENTS})
  list(APPEND EXTRA_COMPONENT_DIRS "$ENV{SB_EXTRA_COMPONENTS}")
else()
  message(FATAL_ERROR "SB_EXTRA_COMPONENTS not set: build via `nix build` or inside `nix develop`")
endif()
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(server_buddy_p4)
