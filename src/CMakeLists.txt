cmake_minimum_required(VERSION 3.21)

include(GNUInstallDirs)

# ##############################################################################
# Generate autoconf.h from template
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/autoconf.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/autoconf.h" @ONLY)

# ##############################################################################
# Require PAM development headers. PAM headers are expected to be present in
# production (pam-devel on RHEL/Fedora). pam_entry.c (the PAM entry points) is
# the ONLY consumer of pam_dep; the core object library and the CLI deliberately
# exclude it so tests can run without linking against libpam.
find_library(PAM_LIBRARY pam REQUIRED)
find_path(PAM_INCLUDE_DIR security/pam_modules.h REQUIRED)
message(STATUS "PAM library: ${PAM_LIBRARY}")
message(STATUS "PAM include: ${PAM_INCLUDE_DIR}")

add_library(pam_dep INTERFACE)
target_include_directories(pam_dep INTERFACE ${PAM_INCLUDE_DIR})
target_link_libraries(pam_dep INTERFACE ${PAM_LIBRARY})

# ##############################################################################
# Require libxcrypt (crypt_r(3) / crypt_gensalt_ra(3)).
#
# We use pkg_check_modules with IMPORTED_TARGET so downstream targets link
# PkgConfig::LIBXCRYPT directly rather than carrying raw variable lists. This
# also makes the build explicitly depend on the libxcrypt package — not glibc's
# legacy libcrypt — matching the RPM Requires/BuildRequires. crypt_gensalt_ra(3)
# is a libxcrypt extension not present in glibc crypt. On RHEL/Fedora: install
# libxcrypt-devel.  On Debian/Ubuntu: libxcrypt-dev.
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXCRYPT REQUIRED IMPORTED_TARGET libxcrypt)
message(STATUS "libxcrypt version: ${LIBXCRYPT_VERSION}")

# ##############################################################################
# Optional: SELinux support via selinux_restorecon(3).
#
# WHY: atomic_write_passwd() creates a temp file in the same directory as the
# destination (path.XXXXXX → path), so the temp file inherits the correct
# SELinux label from the parent directory — rename(2) never changes labels. This
# means the implementation is already SELinux-safe in the common case.
#
# However, selinux_restorecon(3) is called after the rename as a defence against
# the edge case where the parent directory itself was created with the wrong
# context (e.g. by a pre-existing script that didn't trigger the correct type
# transition). restorecon resets the label to whatever policy says the file at
# that path should have.
#
# All conditionality is encapsulated in selinux_dep: downstream targets link it
# unconditionally and get the right behaviour on both SELinux and non-SELinux
# systems (e.g. Debian) without any per-target ifdefs in this file.
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
# Shared core (OBJECT library).
#
# These sources have NO PAM dependency and are compiled exactly once into an
# OBJECT library consumed by both the PAM module and the CLI. Keeping them
# separate also allows test binaries to link vncpasswd_core directly without
# pulling in libpam.
add_library(vncpasswd_core OBJECT src/pam_fnal_vncpasswd.c
                                  src/syscall_ops_default.c)

target_compile_features(
  vncpasswd_core PUBLIC c_std_23 c_restrict c_function_prototypes
                        c_static_assert)
target_compile_definitions(vncpasswd_core PUBLIC _GNU_SOURCE)
target_include_directories(vncpasswd_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
                                                 ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(vncpasswd_core PUBLIC PkgConfig::LIBXCRYPT selinux_dep)

# ##############################################################################
# PAM module (shared library).
#
# Compiles only pam_entry.c (the PAM entry points that require PAM headers) and
# links vncpasswd_core for the remaining logic. PAM modules must not carry a
# "lib" prefix — the set_target_properties call below enforces this.
add_library(pam_fnal_vncpasswd MODULE src/pam_entry.c)
set_target_properties(pam_fnal_vncpasswd PROPERTIES PREFIX "")
target_link_libraries(pam_fnal_vncpasswd PRIVATE vncpasswd_core pam_dep)
install(TARGETS pam_fnal_vncpasswd LIBRARY DESTINATION ${PAM_MODULE_DIR})

# ##############################################################################
# fnal-vncpasswd CLI tool.
#
# Links vncpasswd_core only — no PAM dependency — so the binary can be installed
# and tested independently of the PAM stack.
add_executable(fnal-vncpasswd src/vncpasswd.c)
target_link_libraries(fnal-vncpasswd PRIVATE vncpasswd_core)
install(TARGETS fnal-vncpasswd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
