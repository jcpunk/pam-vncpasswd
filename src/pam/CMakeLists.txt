# pam/CMakeLists.txt
#
# Builds pam_fnal_vncpasswd.so — the PAM authentication module.
#
# PAM DISCOVERY: PAM is only required for this target, so discovery lives here
# rather than in the top-level build.  REQUIRED is intentionally omitted:
# without pam-devel the configure step will warn rather than abort, allowing the
# CLI and shared library to build on machines without PAM headers (e.g.
# developer workstations, pure-CLI deployments, or CI environments).  The module
# simply won't be built.
#
# SOURCE SPLIT: pam_entry.c   PAM API glue only; the sole consumer of pam_dep.
# Extracts username/password from the PAM handle and calls
# authenticate_vnc_user(). auth.c        Core authentication logic: file
# validation, hash reading, password verification, PAM arg parsing.  No PAM
# headers.
#
# The deliberate exclusion of PAM headers from auth.c means test binaries can
# link auth.c directly without needing pam-devel installed.
#
# NAMING: PAM modules must not carry the "lib" prefix (dlopen looks for
# "pam_fnal_vncpasswd.so", not "libpam_fnal_vncpasswd.so").
# set_target_properties enforces this below.

find_library(PAM_LIBRARY pam)
find_path(PAM_INCLUDE_DIR security/pam_modules.h)

if(NOT PAM_LIBRARY OR NOT PAM_INCLUDE_DIR)
  message(
    WARNING
      "libpam or PAM headers not found — pam_fnal_vncpasswd.so will not be built.\n"
      "Install pam-devel (RHEL/Fedora) or libpam0g-dev (Debian/Ubuntu) to enable it."
  )
  return()
endif()

message(STATUS "PAM library: ${PAM_LIBRARY}")
message(STATUS "PAM include: ${PAM_INCLUDE_DIR}")

add_library(pam_dep INTERFACE)
target_include_directories(pam_dep INTERFACE ${PAM_INCLUDE_DIR})
target_link_libraries(pam_dep INTERFACE ${PAM_LIBRARY})

add_library(pam_fnal_vncpasswd MODULE pam_entry.c auth.c)

set_target_properties(pam_fnal_vncpasswd PROPERTIES PREFIX "")

target_include_directories(pam_fnal_vncpasswd
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(pam_fnal_vncpasswd PRIVATE c_std_11)
target_compile_definitions(pam_fnal_vncpasswd PRIVATE _GNU_SOURCE)

target_link_libraries(pam_fnal_vncpasswd PRIVATE vnc_shared pam_dep)

install(TARGETS pam_fnal_vncpasswd LIBRARY DESTINATION ${PAM_MODULE_DIR})
