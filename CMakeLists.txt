# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13)
project(forgeext C)

set(CMAKE_C_STANDARD 11)
add_compile_options(-Wall -Wextra)

find_package(PkgConfig REQUIRED)
pkg_check_modules(JANSSON REQUIRED jansson)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Everything but the command line, so that each test links what the daemon runs.
add_library(forgeext_core STATIC
  src/caps.c
  src/manifest.c
  src/pkg.c
  src/state.c
  src/install.c
  src/cgroup.c
  src/sandbox.c
  src/netrules.c
  src/super.c
  src/machine.c
  src/run.c
  src/holdkeep.c
  src/httpreq.c
  src/evfeed.c
  src/quota.c
  src/settings.c
  src/api.c
  src/call.c
  src/index.c
  src/fflog.c)
target_include_directories(forgeext_core PUBLIC src
  ${JANSSON_INCLUDE_DIRS} ${LIBARCHIVE_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
find_package(Threads REQUIRED)
target_link_libraries(forgeext_core PUBLIC
  ${JANSSON_LIBRARIES} ${LIBARCHIVE_LIBRARIES} ${SODIUM_LIBRARIES} Threads::Threads)
target_link_directories(forgeext_core PUBLIC
  ${JANSSON_LIBRARY_DIRS} ${LIBARCHIVE_LIBRARY_DIRS} ${SODIUM_LIBRARY_DIRS})

add_executable(forgeext src/main.c)
target_link_libraries(forgeext forgeext_core)
install(TARGETS forgeext RUNTIME DESTINATION bin)

# Host tests: one binary each, exit 0 on a pass. tests/install_test.py
# drives the built forgeext against real archives made with fwup.
# sandbox_test needs root and cgroup v2 (it exits 77 without).
foreach(t caps_test manifest_test version_test state_test super_test holdkeep_test httpreq_test api_test evfeed_test lookups_test settings_test quota_test sandbox_test)
  add_executable(${t} tests/${t}.c)
  target_link_libraries(${t} forgeext_core)
  # CI runs each test by name: one built here and never named in the
  # workflow would build and never run, so the configure refuses it.
  file(READ ${CMAKE_CURRENT_SOURCE_DIR}/.github/workflows/build.yml ci_text)
  string(FIND "${ci_text}" "./build/${t}\n" at)
  if(at EQUAL -1)
    message(FATAL_ERROR "${t} has no step in .github/workflows/build.yml whose run: line ends with ./build/${t}")
  endif()
endforeach()

# install_test's hook for the removal's races: preloaded into the command
# line it drives, never into anything the image carries.
add_library(race_hook MODULE tests/race_hook.c)
set_target_properties(race_hook PROPERTIES PREFIX "")
target_link_libraries(race_hook ${CMAKE_DL_LIBS})
