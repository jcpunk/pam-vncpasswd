# fnal-vncpasswd/CMakeLists.txt
#
# Builds fnal-vncpasswd — the CLI tool for setting a user's VNC password.
#
# SOURCE SPLIT: vncpasswd.c   Password reading (interactive/stdin), option
# parsing, main(). passwd.c      login.defs parsing, salt generation, hashing,
# ensure_dir, atomic_write_passwd.  No PAM dependency.
#
# The deliberate exclusion of PAM from both files means this binary can be
# installed and tested independently of the PAM stack, and test binaries can
# link these sources without needing pam-devel installed.

add_executable(fnal-vncpasswd vncpasswd.c passwd.c)

target_include_directories(fnal-vncpasswd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(fnal-vncpasswd PRIVATE c_std_11)
target_compile_definitions(fnal-vncpasswd PRIVATE _GNU_SOURCE)

target_link_libraries(fnal-vncpasswd PRIVATE vnc_shared selinux_dep)

install(TARGETS fnal-vncpasswd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
