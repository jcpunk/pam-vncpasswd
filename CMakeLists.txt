cmake_minimum_required(VERSION 3.11)

project(pam-vncpasswd C)

# ##############################################################################
# CMake modules
include(GNUInstallDirs)
include(CheckCCompilerFlag)

# ##############################################################################
# Require out-of-source builds
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
  message(
    FATAL_ERROR
      "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory and run cmake from there."
  )
endif(EXISTS "${LOC_PATH}")

# ##############################################################################
# Compiler Sanity Test
check_c_source_compiles("int main(void) { return 0; }" CAN_COMPILE)
if(NOT CAN_COMPILE)
  message(FATAL_ERROR "C compiler is non-functional")
endif(NOT CAN_COMPILE)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C Standard: C${CMAKE_C_STANDARD}")
message(STATUS "Supported C features: ${CMAKE_C_COMPILE_FEATURES}")

# ##############################################################################
# Required Compiler Warnings These warnings help catch common issues
add_compile_options(
  -Wall # Enable most warnings
  -Wextra # Enable extra warnings
  -Wpedantic # ISO C conformance warnings
  -Wconversion # Implicit conversion warnings
  -Wsign-conversion # Sign conversion warnings
  -Wformat=2 # Enhanced format string warnings
  -Wformat-security # Format security issues
  -Wstrict-prototypes # Require function prototypes
  -Wstrict-overflow=2 # Overflow detection (level 2)
  -Wvla # Variable length arrays discouraged
  -Wshadow # Warn on shadowed variables
  -Walloca # Warn on suspicious alloca usage
  -Wcast-qual # Warn on cast removing const/volatile
  -Wcast-align # Warn on alignment-affecting casts
  -Wwrite-strings # String literals are const
  -Wundef # Undefined macro in #if
  -Wmissing-prototypes # Missing function prototypes
  -Wmissing-declarations # Missing declarations
  -Wredundant-decls # Redundant declarations
  -Wnested-externs # Nested extern declarations
  -Winline # Inline function can't be inlined
  -Wdisabled-optimization # Optimization disabled
  -Werror=implicit-function-declaration # Error on implicit declarations
  -Werror # Treat all warnings as errors
)

# Additional hardening for formats
add_compile_options(-D_GLIBCXX_ASSERTIONS)

# Additional GCC features (not supported by all compilers)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(
    -Wlogical-op # Suspicious logical operations
    -Wduplicated-cond # Duplicated conditions
    -Wduplicated-branches # Duplicated branches
    -Wnull-dereference # Potential NULL dereferences
    -Wjump-misses-init # Jump skips variable initialization
  )
endif(CMAKE_C_COMPILER_ID STREQUAL "GNU")

# ##############################################################################
# Find our source code version string
if(NOT DEFINED VERSION OR VERSION STREQUAL "")
  execute_process(
    COMMAND git describe --abbrev=0
    OUTPUT_VARIABLE VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
    RESULT_VARIABLE GIT_RESULT)

  if(GIT_RESULT OR VERSION STREQUAL "")
    message(FATAL_ERROR "Could not identify version")
  endif()
endif()

# ##############################################################################
# Top Level Configuration Variables

if(NOT DEFINED LOGIN_DEFS_PATH)
  set(LOGIN_DEFS_PATH
      "/etc/login.defs"
      CACHE PATH "Path to login.defs")
endif()

if(NOT DEFINED DEFAULT_ENCRYPT_METHOD)
  set(DEFAULT_ENCRYPT_METHOD
      "SHA512"
      CACHE STRING "Default encrypt method if login.defs does not specify")
endif()

#
# yescrypt cost factor (YESCRYPT_COST_FACTOR in login.defs)
# Default is 5 per shadow-utils: N=2^(5+10)=32768, r=32, p=1
# This is passed to crypt_gensalt_ra() as the count parameter.
# NOTE: this is NOT the same as SHA_CRYPT_MAX_ROUNDS.
# Do NOT set this to 65536 — that value is for SHA-crypt only.
#
if(NOT DEFINED DEFAULT_YESCRYPT_COST)
  set(DEFAULT_YESCRYPT_COST
      5
      CACHE STRING "Default yescrypt cost factor (YESCRYPT_COST_FACTOR)")
endif()

if(NOT DEFINED DEFAULT_SHA_CRYPT_ROUNDS)
  set(DEFAULT_SHA_CRYPT_ROUNDS
      65536
      CACHE STRING "Default SHA-crypt rounds (SHA_CRYPT_MAX_ROUNDS)")
endif()

if(NOT DEFINED VNC_PASSWD_DIR)
  set(VNC_PASSWD_DIR
      ".config/vnc"
      CACHE STRING "VNC password subdirectory under user home (XDG convention)")
endif()

if(NOT DEFINED VNC_PASSWD_FILE)
  set(VNC_PASSWD_FILE
      "fnal_vncpasswd"
      CACHE STRING "VNC password filename within VNC_PASSWD_DIR")
endif()

if(NOT DEFINED MAX_PASSWORD_LENGTH)
  set(MAX_PASSWORD_LENGTH
      8
      CACHE STRING
            "Maximum password length (VNC RFB protocol limit is 8 characters)")
endif()

if(NOT DEFINED MIN_PASSWORD_LENGTH)
  set(MIN_PASSWORD_LENGTH
      1
      CACHE STRING "Minimum password length enforced by fnal-vncpasswd")
endif()

# PAM module installation directory
if(NOT DEFINED PAM_MODULE_DIR)
  if(EXISTS "/usr/lib64/security")
    set(PAM_MODULE_DIR
        "/usr/lib64/security"
        CACHE PATH "PAM module installation directory")
  else()
    set(PAM_MODULE_DIR
        "${CMAKE_INSTALL_FULL_LIBDIR}/security"
        CACHE PATH "PAM module installation directory")
  endif()
endif()

# ##############################################################################
# Validate Configuration
if(NOT DEFAULT_YESCRYPT_COST MATCHES "^[0-9]+$")
  message(
    FATAL_ERROR
      "DEFAULT_YESCRYPT_COST must be a non-negative integer (got: '${DEFAULT_YESCRYPT_COST}')"
  )
endif()

if(NOT DEFAULT_SHA_CRYPT_ROUNDS MATCHES "^[0-9]+$")
  message(
    FATAL_ERROR
      "DEFAULT_SHA_CRYPT_ROUNDS must be a non-negative integer (got: '${DEFAULT_SHA_CRYPT_ROUNDS}')"
  )
endif()

if(NOT MIN_PASSWORD_LENGTH MATCHES "^[0-9]+$")
  message(
    FATAL_ERROR
      "MIN_PASSWORD_LENGTH must be a non-negative integer (got: '${MIN_PASSWORD_LENGTH}')"
  )
endif()

if(NOT MAX_PASSWORD_LENGTH MATCHES "^[0-9]+$")
  message(
    FATAL_ERROR
      "MAX_PASSWORD_LENGTH must be a non-negative integer (got: '${MAX_PASSWORD_LENGTH}')"
  )
endif()

# ##############################################################################
# task focused cmake
include(docs/CMakeLists.txt)
include(src/CMakeLists.txt)
include(test/CMakeLists.txt)

# ##############################################################################
# Print out state summary
message(STATUS "${CMAKE_PROJECT_NAME} - ${VERSION}")
message(STATUS "Compile Time Configuration:")
message(STATUS "  LOGIN_DEFS_PATH           = ${LOGIN_DEFS_PATH}")
message(STATUS "  DEFAULT_ENCRYPT_METHOD    = ${DEFAULT_ENCRYPT_METHOD}")
message(STATUS "  DEFAULT_YESCRYPT_COST     = ${DEFAULT_YESCRYPT_COST}")
message(STATUS "  DEFAULT_SHA_CRYPT_ROUNDS  = ${DEFAULT_SHA_CRYPT_ROUNDS}")
message(STATUS "  VNC_PASSWD_DIR            = ${VNC_PASSWD_DIR}")
message(STATUS "  VNC_PASSWD_FILE           = ${VNC_PASSWD_FILE}")
message(STATUS "  MAX_PASSWORD_LENGTH       = ${MAX_PASSWORD_LENGTH}")
message(STATUS "  MIN_PASSWORD_LENGTH       = ${MIN_PASSWORD_LENGTH}")
message(STATUS "  PAM_MODULE_DIR            = ${PAM_MODULE_DIR}")
