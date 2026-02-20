cmake_minimum_required(VERSION 3.21)

project(fnal-vncpasswd C)

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
  -Werror # Treat all warnings as errors
  -Wall # Enable most warnings
  -Wextra # Enable extra warnings
  -Wpedantic # ISO C conformance warnings
  -Walloca # Warn on suspicious alloca usage
  -Wcast-align # Warn on alignment-affecting casts
  -Wcast-qual # Warn on cast removing const/volatile
  -Wconversion # Implicit conversion warnings
  -Wdisabled-optimization # Optimization disabled
  -Wdouble-promotion # Implicit float-to-double promotion
  -Werror=implicit-function-declaration # Error on implicit declarations
  -Wformat=2 # Enhanced format string warnings
  -Wformat-security # Format security issues
  -Winline # Inline function can't be inlined
  -Wmissing-declarations # Missing declarations
  -Wmissing-field-initializers # Struct fields left uninitialized
  -Wmissing-prototypes # Missing function prototypes
  -Wnested-externs # Nested extern declarations
  -Wnull-dereference # Potential NULL dereferences
  -Wredundant-decls # Redundant declarations
  -Wshadow # Warn on shadowed variables
  -Wsign-conversion # Sign conversion warnings
  -Wstrict-overflow=2 # Overflow detection (level 2)
  -Wstrict-prototypes # Require function prototypes
  -Wundef # Undefined macro in #if
  -Wvla # Variable length arrays discouraged
  -Wwrite-strings # String literals are const
)

# Ensure our behavior modes are defined
add_compile_definitions(_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)

# Additional GCC features (not supported by all compilers)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(
    -Warith-conversion # Implicit conversions in arithmetic
    -Wduplicated-branches # Identical if/else branches
    -Wduplicated-cond # Duplicated conditions in if/else chains
    -Wjump-misses-init # goto skips variable initialization
    -Wlogical-op # Suspicious logical operations
    -Wstringop-overflow # String operations writing past buffer end
    -Wtrampolines # Nested functions requiring executable stack
  )
endif(CMAKE_C_COMPILER_ID STREQUAL "GNU")

# ##############################################################################
# Find our source code version string
if(NOT DEFINED VERSION OR VERSION STREQUAL "")
  execute_process(
    COMMAND git describe --tags --abbrev=0
    OUTPUT_VARIABLE VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
    RESULT_VARIABLE GIT_RESULT)

  if(GIT_RESULT OR VERSION STREQUAL "")
    message(FATAL_ERROR "Could not identify version")
  endif()
endif()

# ##############################################################################
# Top Level System Variables, these are pretty much a public api

set(_expected_pam_dir "${CMAKE_INSTALL_FULL_LIBDIR}/security")

if(DEFINED PAM_MODULE_DIR AND NOT PAM_MODULE_DIR STREQUAL _expected_pam_dir)
  message(WARNING "PAM_MODULE_DIR (${PAM_MODULE_DIR}) differs from expected "
                  "(${_expected_pam_dir}) for this platform")
endif()

if(NOT DEFINED VNC_PASSWD_DIR)
  set(VNC_PASSWD_DIR
      ".config/vnc"
      CACHE STRING "VNC password subdirectory under user home (XDG convention)")
endif()

if(NOT DEFINED VNC_PASSWD_FILE)
  set(VNC_PASSWD_FILE
      "fnal-vncpasswd"
      CACHE STRING "VNC password filename within VNC_PASSWD_DIR")
endif()

set(MAX_PASSWORD_LENGTH 8) # RFB protocol limit is 8

# ##############################################################################
# Top Level Configuration Variables

if(NOT DEFINED DEFAULT_ENCRYPT_METHOD)
  set(DEFAULT_ENCRYPT_METHOD
      "YESCRYPT"
      CACHE STRING "Default encrypt method if login.defs does not specify")
endif()

if(NOT DEFINED VNC_MIN_PASSWORD_LENGTH)
  set(VNC_MIN_PASSWORD_LENGTH
      6
      CACHE STRING "Minimum password length enforced by fnal-vncpasswd")
endif()

# ##############################################################################
# Validate Configuration
if(NOT VNC_MIN_PASSWORD_LENGTH MATCHES "^[0-8]+$")
  message(
    FATAL_ERROR
      "VNC_MIN_PASSWORD_LENGTH must be a non-negative integer (got: '${VNC_MIN_PASSWORD_LENGTH}')"
  )
endif()

if(NOT VNC_MAX_PASSWORD_LENGTH EQUAL 8)
  message(
    FATAL_ERROR "VNC_MAX_PASSWORD_LENGTH must be 8 (VNC RFB protocol limit). "
                "Got: ${VNC_MAX_PASSWORD_LENGTH}")
endif()

# ##############################################################################
# task focused cmake
add_subdirectory(docs)
add_subdirectory(src)
add_subdirectory(test)

# ##############################################################################
# Print out state summary
message(STATUS "${CMAKE_PROJECT_NAME} - ${VERSION}")
message(STATUS "Compile Time Configuration:")
message(STATUS "  PAM_MODULE_DIR            = ${PAM_MODULE_DIR}")
message(STATUS "  VNC_PASSWD_DIR            = ${VNC_PASSWD_DIR}")
message(STATUS "  VNC_PASSWD_FILE           = ${VNC_PASSWD_FILE}")
message(STATUS "  VNC_MAX_PASSWORD_LENGTH   = ${VNC_MAX_PASSWORD_LENGTH}")
message(STATUS "  VNC_MIN_PASSWORD_LENGTH   = ${VNC_MIN_PASSWORD_LENGTH}")
