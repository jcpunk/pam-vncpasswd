cmake_minimum_required(VERSION 3.21)

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

# ##############################################################################
# Subdirectories
# ##############################################################################

add_subdirectory(shared)
add_subdirectory(pam)
add_subdirectory(fnal-vncpasswd)
