# pam/CMakeLists.txt
#
# Builds pam_fnal_vncpasswd.so — the PAM authentication module.
#
# SOURCE SPLIT: pam_entry.c  PAM API glue only; extracts username/password from
# the PAM handle and calls authenticate_vnc_user(). auth.c       Core
# authentication logic: file validation, hash reading, password verification,
# PAM arg parsing.
#
# NAMING: PAM modules must not carry the "lib" prefix dlopen looks for
# "pam_fnal_vncpasswd.so", not "libpam_fnal_vncpasswd.so" Use of "_" not "-" is
# the expected naming for PAM modules

find_library(PAM_LIBRARY NAMES pam REQUIRED)
find_path(PAM_INCLUDE_DIR NAMES security/pam_modules.h REQUIRED)

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
