# shared/CMakeLists.txt
#
# Builds vnc_shared: the OBJECT library consumed by both the PAM module and the
# CLI.  Contains only code that is genuinely used by both: -
# syscall_ops_default.c  production syscall dispatch table - vnc_path.c VNC
# password file path construction
#
# WHY OBJECT LIBRARY: An OBJECT library compiles sources exactly once and lets
# multiple targets (pam_fnal_vncpasswd MODULE, fnal-vncpasswd EXECUTABLE)
# include the same object files without re-compiling or creating an intermediate
# shared/static library.  This avoids the link-time visibility and soname
# complications that would arise from a shared library, and keeps the build
# graph simple.

add_library(vnc_shared OBJECT syscall_ops_default.c vnc_path.c)

target_compile_features(
  vnc_shared PRIVATE c_std_11 c_restrict c_function_prototypes c_static_assert)
target_compile_definitions(vnc_shared PRIVATE _GNU_SOURCE)

# Both the generated autoconf.h (in the top-level binary dir) and the shared
# headers (in this source dir) must be on the include path for all consumers.
target_include_directories(
  vnc_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_BINARY_DIR} # for generated autoconf.h
)

target_link_libraries(vnc_shared PUBLIC PkgConfig::LIBXCRYPT)
