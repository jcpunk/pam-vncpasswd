cmake_minimum_required(VERSION 3.14)

# ##############################################################################
# Load CMake provided modules
include(GNUInstallDirs)

# ##############################################################################
# Generate autoconf.h from template
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/autoconf.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/autoconf.h" @ONLY)

# ##############################################################################
# Source files shared between PAM module, CLI, and tests
set(PAM_VNCPASSWD_LIB_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pam_vncpasswd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/syscall_ops_default.c)

# ##############################################################################
# Check for PAM development headers
find_library(PAM_LIBRARY pam)
find_path(PAM_INCLUDE_DIR security/pam_modules.h)

if(PAM_LIBRARY AND PAM_INCLUDE_DIR)
  set(HAVE_PAM TRUE)
  message(STATUS "PAM found: ${PAM_LIBRARY}")
else()
  set(HAVE_PAM FALSE)
  message(
    STATUS
      "PAM development headers not found — skipping pam_vncpasswd.so build")
endif()

# ##############################################################################
# PAM module (shared library)
if(HAVE_PAM)
  add_library(pam_vncpasswd MODULE ${PAM_VNCPASSWD_LIB_SOURCES})

  target_compile_features(
    pam_vncpasswd PRIVATE c_std_23 c_restrict c_function_prototypes
                          c_static_assert)

  target_compile_definitions(pam_vncpasswd PRIVATE _GNU_SOURCE HAVE_PAM)

  target_include_directories(
    pam_vncpasswd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                          ${CMAKE_CURRENT_BINARY_DIR} ${PAM_INCLUDE_DIR})

  target_link_libraries(pam_vncpasswd PRIVATE crypt ${PAM_LIBRARY})

  # PAM modules must not have an "lib" prefix
  set_target_properties(pam_vncpasswd PROPERTIES PREFIX "")

  install(TARGETS pam_vncpasswd LIBRARY DESTINATION ${PAM_MODULE_DIR})
endif(HAVE_PAM)

# ##############################################################################
# fnal-vncpasswd CLI tool
add_executable(fnal-vncpasswd ${CMAKE_CURRENT_SOURCE_DIR}/src/vncpasswd.c
                              ${PAM_VNCPASSWD_LIB_SOURCES})

target_compile_features(
  fnal-vncpasswd PRIVATE c_std_23 c_restrict c_function_prototypes
                         c_static_assert)

target_compile_definitions(fnal-vncpasswd PRIVATE _GNU_SOURCE)

target_include_directories(fnal-vncpasswd
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                   ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(fnal-vncpasswd PRIVATE crypt)

install(TARGETS fnal-vncpasswd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
