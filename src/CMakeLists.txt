cmake_minimum_required(VERSION 3.21)
project(
  pam_fnal_vncpasswd
  VERSION 1.0.0
  LANGUAGES C)

include(GNUInstallDirs)

# ##############################################################################
# Build-time configuration
# ##############################################################################

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/autoconf.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/autoconf.h" @ONLY)

# ##############################################################################
# Shared dependencies
# ##############################################################################

# libxcrypt: crypt_r(3), crypt_gensalt_ra(3) — not in glibc on RHEL 9+
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXCRYPT REQUIRED IMPORTED_TARGET libxcrypt)
message(STATUS "libxcrypt version: ${LIBXCRYPT_VERSION}")

# Optional SELinux: selinux_restorecon(3) after atomic password file write. All
# conditionality lives here; downstream targets link selinux_dep unconditionally
# and get the right behaviour on both SELinux and non-SELinux hosts.
add_library(selinux_dep INTERFACE)
find_library(SELINUX_LIBRARY selinux)
find_path(SELINUX_INCLUDE_DIR selinux/selinux.h)
if(SELINUX_LIBRARY AND SELINUX_INCLUDE_DIR)
  message(STATUS "SELinux support enabled: ${SELINUX_LIBRARY}")
  target_compile_definitions(selinux_dep INTERFACE HAVE_SELINUX)
  target_include_directories(selinux_dep INTERFACE ${SELINUX_INCLUDE_DIR})
  target_link_libraries(selinux_dep INTERFACE ${SELINUX_LIBRARY})
else()
  message(STATUS "libselinux not found — selinux_restorecon disabled")
endif()

# ##############################################################################
# Subdirectories
# ##############################################################################

add_subdirectory(shared)
add_subdirectory(pam)
add_subdirectory(fnal-vncpasswd)
