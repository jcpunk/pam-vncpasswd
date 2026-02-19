cmake_minimum_required(VERSION 3.11)
include(GNUInstallDirs)

find_program(ASCIIDOCTOR asciidoctor)
find_program(ASCIIDOC asciidoc)
find_program(A2X a2x)

# ##############################################################################
# Figure out how to build manpages
if(ASCIIDOCTOR)
  message(STATUS "Using asciidoctor for manpage generation")
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
    COMMAND ${ASCIIDOCTOR} -b manpage -o ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
            ${PROJECT_SOURCE_DIR}/docs/pam_fnal_vncpasswd.8.adoc
    DEPENDS ${PROJECT_SOURCE_DIR}/docs/pam_fnal_vncpasswd.8.adoc
    COMMENT "Building pam_fnal_vncpasswd manpage with asciidoctor"
    VERBATIM)
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1
    COMMAND ${ASCIIDOCTOR} -b manpage -o ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1
            ${PROJECT_SOURCE_DIR}/docs/fnal-vncpasswd.1.adoc
    DEPENDS ${PROJECT_SOURCE_DIR}/docs/fnal-vncpasswd.1.adoc
    COMMENT "Building fnal-vncpasswd manpage with asciidoctor"
    VERBATIM)
  add_custom_target(doc ALL DEPENDS ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
                                    ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1)
elseif(ASCIIDOC AND A2X)
  message(STATUS "Using asciidoc/a2x for manpage generation")
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
    COMMAND ${A2X} --doctype manpage --format manpage -D ${PROJECT_BINARY_DIR}
            ${PROJECT_SOURCE_DIR}/docs/pam_fnal_vncpasswd.8.adoc
    DEPENDS ${PROJECT_SOURCE_DIR}/docs/pam_fnal_vncpasswd.8.adoc
    COMMENT "Building pam_fnal_vncpasswd manpage with a2x"
    VERBATIM)
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1
    COMMAND ${A2X} --doctype manpage --format manpage -D ${PROJECT_BINARY_DIR}
            ${PROJECT_SOURCE_DIR}/docs/fnal-vncpasswd.1.adoc
    DEPENDS ${PROJECT_SOURCE_DIR}/docs/fnal-vncpasswd.1.adoc
    COMMENT "Building fnal-vncpasswd manpage with a2x"
    VERBATIM)
  add_custom_target(doc ALL DEPENDS ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
                                    ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1)
else()
  message(STATUS "No asciidoctor or asciidoc/a2x found — skipping manpage build")
  add_custom_target(doc ALL COMMENT "No doc tool available; manpages not built")
endif()

# Install manpages (only if built)
if(ASCIIDOCTOR OR (ASCIIDOC AND A2X))
  install(FILES ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
          DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
  install(FILES ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1
          DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
endif()

# Install example PAM config
install(FILES ${PROJECT_SOURCE_DIR}/docs/pam_fnal_vncpasswd.conf.example
        DESTINATION ${CMAKE_INSTALL_DATADIR}/pam-vncpasswd
        OPTIONAL)
