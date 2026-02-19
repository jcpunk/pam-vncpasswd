# pam/CMakeLists.txt
#
# Builds pam_fnal_vncpasswd.so — the PAM authentication module.
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

add_library(pam_fnal_vncpasswd MODULE pam_entry.c auth.c)

set_target_properties(pam_fnal_vncpasswd PROPERTIES PREFIX "")

target_include_directories(pam_fnal_vncpasswd
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(pam_fnal_vncpasswd PRIVATE vnc_shared pam_dep)

install(TARGETS pam_fnal_vncpasswd LIBRARY DESTINATION ${PAM_MODULE_DIR})
