cmake_minimum_required(VERSION 3.14)

# ##############################################################################
# Load CMake provided modules
include(GNUInstallDirs)

# ##############################################################################
# Generate autoconf.h from template
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/autoconf.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/autoconf.h" @ONLY)

# ##############################################################################
# Source files shared between PAM module, CLI, and tests.
# These files have NO PAM dependency and are compiled into test binaries.
set(PAM_VNCPASSWD_LIB_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pam_fnal_vncpasswd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/syscall_ops_default.c)

# ##############################################################################
# Require PAM development headers.
# PAM headers are expected to be present in production (pam-devel on RHEL/Fedora).
# pam_entry.c (the PAM entry points) is compiled ONLY into pam_fnal_vncpasswd.so,
# not into test binaries, so tests can run without linking against libpam.
find_library(PAM_LIBRARY pam)
find_path(PAM_INCLUDE_DIR security/pam_modules.h)

if(NOT PAM_LIBRARY OR NOT PAM_INCLUDE_DIR)
  message(
    FATAL_ERROR
      "PAM development headers not found (install pam-devel / libpam0g-dev).\n"
      "PAM is required to build pam_fnal_vncpasswd.so.\n"
      "If you only need tests, pass -DPAM_LIBRARY=/path/to/libpam.so "
      "-DPAM_INCLUDE_DIR=/usr/include or install the pam-devel package.")
endif()

message(STATUS "PAM library: ${PAM_LIBRARY}")
message(STATUS "PAM include: ${PAM_INCLUDE_DIR}")

# ##############################################################################
# Optional: SELinux support via selinux_restorecon(3)
#
# WHY:
# atomic_write_passwd() creates a temp file in the same directory as the
# destination (path.XXXXXX → path), so the temp file inherits the correct
# SELinux label from the parent directory — rename(2) never changes labels.
# This means the implementation is already SELinux-safe in the common case.
#
# However, selinux_restorecon(3) is called after the rename as a defence
# against the edge case where the parent directory itself was created with
# the wrong context (e.g. by a pre-existing script that didn't trigger the
# correct type transition). restorecon resets the label to whatever policy
# says the file at that path should have.
#
# NOTE ON USERNAME SALTING:
# The password hash does NOT incorporate the username. The random salt from
# crypt_gensalt_ra(3) already guarantees uniqueness, and the file-ownership
# check in validate_passwd_file() (st.st_uid == user's UID) defeats
# hash-copying attacks without silently altering what the user typed.
find_library(SELINUX_LIBRARY selinux)
find_path(SELINUX_INCLUDE_DIR selinux/selinux.h)

if(SELINUX_LIBRARY AND SELINUX_INCLUDE_DIR)
  set(HAVE_SELINUX TRUE)
  message(STATUS "SELinux support enabled: ${SELINUX_LIBRARY}")
else()
  set(HAVE_SELINUX FALSE)
  message(STATUS "libselinux not found — selinux_restorecon disabled")
endif()

# ##############################################################################
# PAM module (shared library)
# Compiles core logic + pam_entry.c (PAM entry points that need PAM headers)
add_library(pam_fnal_vncpasswd MODULE
            ${PAM_VNCPASSWD_LIB_SOURCES}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/pam_entry.c)

target_compile_features(
  pam_fnal_vncpasswd PRIVATE c_std_23 c_restrict c_function_prototypes
                             c_static_assert)

target_compile_definitions(pam_fnal_vncpasswd PRIVATE _GNU_SOURCE)

target_include_directories(
  pam_fnal_vncpasswd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                             ${CMAKE_CURRENT_BINARY_DIR} ${PAM_INCLUDE_DIR})

set(PAM_MODULE_LIBS crypt ${PAM_LIBRARY})
if(HAVE_SELINUX)
  target_compile_definitions(pam_fnal_vncpasswd PRIVATE HAVE_SELINUX)
  target_include_directories(pam_fnal_vncpasswd PRIVATE ${SELINUX_INCLUDE_DIR})
  list(APPEND PAM_MODULE_LIBS ${SELINUX_LIBRARY})
endif()

target_link_libraries(pam_fnal_vncpasswd PRIVATE ${PAM_MODULE_LIBS})

# PAM modules must not have a "lib" prefix
set_target_properties(pam_fnal_vncpasswd PROPERTIES PREFIX "")

install(TARGETS pam_fnal_vncpasswd LIBRARY DESTINATION ${PAM_MODULE_DIR})

# ##############################################################################
# fnal-vncpasswd CLI tool
add_executable(fnal-vncpasswd ${CMAKE_CURRENT_SOURCE_DIR}/src/vncpasswd.c
                              ${PAM_VNCPASSWD_LIB_SOURCES})

target_compile_features(
  fnal-vncpasswd PRIVATE c_std_23 c_restrict c_function_prototypes
                         c_static_assert)

target_compile_definitions(fnal-vncpasswd PRIVATE _GNU_SOURCE)

set(VNCPASSWD_LIBS crypt)
if(HAVE_SELINUX)
  target_compile_definitions(fnal-vncpasswd PRIVATE HAVE_SELINUX)
  target_include_directories(fnal-vncpasswd PRIVATE ${SELINUX_INCLUDE_DIR})
  list(APPEND VNCPASSWD_LIBS ${SELINUX_LIBRARY})
endif()

target_include_directories(fnal-vncpasswd
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                   ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(fnal-vncpasswd PRIVATE ${VNCPASSWD_LIBS})

install(TARGETS fnal-vncpasswd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
