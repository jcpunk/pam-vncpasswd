# pam/CMakeLists.txt
#
# Builds pam_fnal_vncpasswd.so — the PAM authentication module.
#
# SOURCE SPLIT: pam_entry.c   PAM API glue only; extracts username/password from
# the PAM handle and calls authenticate_vnc_user(). auth.c        Core
# authentication logic: file validation, hash reading, password verification,
# PAM arg parsing.
#
# NAMING: PAM modules must not carry the "lib" prefix.  dlopen looks for
# "pam_fnal_vncpasswd.so", not "libpam_fnal_vncpasswd.so".  Use of "_" not "-"
# is the expected naming for PAM modules.
#
# CRYPTO BACKEND: Exactly one of the following must be available at configure
# time (searched in order of preference): OpenSSL  >= 1.1  → HAVE_OPENSSL
# LibreSSL >= 3.0  → HAVE_LIBRESSL  (also sets OpenSSL targets; detected via
# LIBRESSL_VERSION_TEXT in <openssl/opensslv.h>) GnuTLS   >= 3.6  → HAVE_GNUTLS
# The selected backend is exposed as the imported interface target "crypto_dep"
# so auth.c does not need backend-specific include paths.

cmake_minimum_required(VERSION 3.21)
# ---------------------------------------------------------------------------
# PAM
# ---------------------------------------------------------------------------
find_library(PAM_LIBRARY NAMES pam REQUIRED)
find_path(PAM_INCLUDE_DIR NAMES security/pam_modules.h REQUIRED)

message(STATUS "PAM library : ${PAM_LIBRARY}")
message(STATUS "PAM include : ${PAM_INCLUDE_DIR}")

add_library(pam_dep INTERFACE)
target_include_directories(pam_dep INTERFACE ${PAM_INCLUDE_DIR})
target_link_libraries(pam_dep INTERFACE ${PAM_LIBRARY})

# ---------------------------------------------------------------------------
# Crypto backend — first found wins
# ---------------------------------------------------------------------------
add_library(crypto_dep INTERFACE)

# OpenSSL / LibreSSL  (LibreSSL exposes the same CMake targets as OpenSSL)
find_package(OpenSSL QUIET COMPONENTS Crypto)

if(OpenSSL_FOUND)
  # Distinguish LibreSSL from OpenSSL by inspecting the version header. LibreSSL
  # defines LIBRESSL_VERSION_TEXT in <openssl/opensslv.h>.
  include(CheckSymbolExists)
  set(CMAKE_REQUIRED_INCLUDES "${OPENSSL_INCLUDE_DIR}")
  check_symbol_exists(LIBRESSL_VERSION_TEXT "openssl/opensslv.h"
                      _HAVE_LIBRESSL_MARKER)
  unset(CMAKE_REQUIRED_INCLUDES)

  if(_HAVE_LIBRESSL_MARKER)
    # LibreSSL — version string lives in LIBRESSL_VERSION_TEXT; extract it with
    # a small try-compile so we don't need to parse headers manually.
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/libressl_ver.c"
         "#include <openssl/opensslv.h>\n"
         "const char *v = LIBRESSL_VERSION_TEXT;\n")
    try_run(_run_result _compile_result "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/libressl_ver.c"
            RUN_OUTPUT_VARIABLE _libressl_ver_out)
    # Fallback: use the OpenSSL-compat version reported by find_package
    set(_CRYPTO_VERSION "${OPENSSL_VERSION} (LibreSSL compat)")
    message(STATUS "Crypto backend : LibreSSL ${_CRYPTO_VERSION}")
    target_compile_definitions(crypto_dep INTERFACE HAVE_LIBRESSL=1)
    set(HAVE_LIBRESSL 1)
  else()
    set(_CRYPTO_VERSION "${OPENSSL_VERSION}")
    message(STATUS "Crypto backend : OpenSSL ${_CRYPTO_VERSION}")
    target_compile_definitions(crypto_dep INTERFACE HAVE_OPENSSL=1)
    set(HAVE_OPENSSL 1)
  endif()

  target_link_libraries(crypto_dep INTERFACE OpenSSL::Crypto)
  target_include_directories(crypto_dep INTERFACE "${OPENSSL_INCLUDE_DIR}")

else()
  # GnuTLS
  find_package(GnuTLS REQUIRED)
  message(STATUS "Crypto backend : GnuTLS ${GnuTLS_VERSION}")
  target_compile_definitions(crypto_dep INTERFACE HAVE_GNUTLS=1)
  target_link_libraries(crypto_dep INTERFACE GnuTLS::GnuTLS)
  target_include_directories(crypto_dep INTERFACE "${GNUTLS_INCLUDE_DIR}")
  set(HAVE_GNUTLS 1)
endif()

# ---------------------------------------------------------------------------
# PAM module
# ---------------------------------------------------------------------------
add_library(pam_fnal_vncpasswd MODULE pam_entry.c auth.c)

set_target_properties(pam_fnal_vncpasswd PROPERTIES PREFIX "")

target_include_directories(pam_fnal_vncpasswd
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(pam_fnal_vncpasswd PRIVATE c_std_11)
target_compile_definitions(pam_fnal_vncpasswd PRIVATE _GNU_SOURCE)
target_link_libraries(pam_fnal_vncpasswd PRIVATE vnc_shared pam_dep crypto_dep)

install(TARGETS pam_fnal_vncpasswd LIBRARY DESTINATION ${PAM_MODULE_DIR})
