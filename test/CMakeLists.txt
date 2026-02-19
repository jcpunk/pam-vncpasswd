cmake_minimum_required(VERSION 3.21)

# ##############################################################################
# Project / modules

include(GNUInstallDirs)
include(CTest)
enable_testing()

# ##############################################################################
# Coverage configuration (compiler aware, optional)

set(HAVE_COVERAGE_TOOLS OFF)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")

  find_program(LCOV_EXEC lcov)
  find_program(GENHTML_EXEC genhtml)

  if(LCOV_EXEC AND GENHTML_EXEC)
    set(HAVE_COVERAGE_TOOLS ON)

    set(COVERAGE_COMPILE_FLAGS
        -g --coverage -fdebug-prefix-map=${CMAKE_BINARY_DIR}=.
        -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.)

    set(COVERAGE_LINK_FLAGS --coverage)

    message(STATUS "Coverage enabled: GCC + lcov")
  endif(LCOV_EXEC AND GENHTML_EXEC)

elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")

  find_program(LLVM_PROFDATA_EXEC llvm-profdata)
  find_program(LLVM_COV_EXEC llvm-cov)
  find_program(GENHTML_EXEC genhtml)

  if(LLVM_PROFDATA_EXEC
     AND LLVM_COV_EXEC
     AND GENHTML_EXEC)
    set(HAVE_COVERAGE_TOOLS ON)

    set(COVERAGE_COMPILE_FLAGS
        -g -fprofile-instr-generate -fcoverage-mapping
        -fdebug-prefix-map=${CMAKE_BINARY_DIR}=.
        -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.)

    set(COVERAGE_LINK_FLAGS -fprofile-instr-generate)

    message(STATUS "Coverage enabled: Clang + llvm-cov")
  endif()

endif()

# ##############################################################################
# Helper macro

macro(add_unit_test TEST_NAME)
  # vncpasswd_core is an OBJECT library; linking it pulls in its compiled
  # objects (pam_fnal_vncpasswd.c, syscall_ops_default.c) and its PUBLIC
  # dependencies (PkgConfig::LIBXCRYPT, selinux_dep).
  add_executable(${TEST_NAME} test/${TEST_NAME}.c)

  target_compile_definitions(${TEST_NAME} PRIVATE _GNU_SOURCE)
  target_compile_features(
    ${TEST_NAME} PRIVATE c_std_23 c_restrict c_function_prototypes
                         c_static_assert)

  target_include_directories(
    ${TEST_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src
                         ${CMAKE_SOURCE_DIR}/test ${CMAKE_BINARY_DIR})

  target_link_libraries(${TEST_NAME} PRIVATE vncpasswd_core)

  if(HAVE_COVERAGE_TOOLS)
    target_compile_options(${TEST_NAME} PRIVATE ${COVERAGE_COMPILE_FLAGS})
    target_link_options(${TEST_NAME} PRIVATE ${COVERAGE_LINK_FLAGS})
  endif()

  list(APPEND UNIT_TEST_BINARIES ${TEST_NAME})
  set(UNIT_TEST_BINARIES
      "${UNIT_TEST_BINARIES}"
      CACHE INTERNAL "")

  add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endmacro()

# ##############################################################################
# Tests

if(BUILD_TESTING)
  add_unit_test(test_pam_fnal_vncpasswd)

  # test_vncpasswd also needs vncpasswd.c (with VNCPASSWD_TESTING to suppress
  # main()) Link vncpasswd_core to pull in the shared core objects and their
  # deps.
  add_executable(test_vncpasswd ${CMAKE_SOURCE_DIR}/test/test_vncpasswd.c
                                ${CMAKE_SOURCE_DIR}/src/vncpasswd.c)

  target_compile_definitions(test_vncpasswd PRIVATE _GNU_SOURCE
                                                    VNCPASSWD_TESTING)
  target_compile_features(
    test_vncpasswd PRIVATE c_std_23 c_restrict c_function_prototypes
                           c_static_assert)
  target_include_directories(
    test_vncpasswd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src
                           ${CMAKE_SOURCE_DIR}/test ${CMAKE_BINARY_DIR})

  target_link_libraries(test_vncpasswd PRIVATE vncpasswd_core)

  if(HAVE_COVERAGE_TOOLS)
    target_compile_options(test_vncpasswd PRIVATE ${COVERAGE_COMPILE_FLAGS})
    target_link_options(test_vncpasswd PRIVATE ${COVERAGE_LINK_FLAGS})
  endif()

  list(APPEND UNIT_TEST_BINARIES test_vncpasswd)
  set(UNIT_TEST_BINARIES
      "${UNIT_TEST_BINARIES}"
      CACHE INTERNAL "")
  add_test(NAME test_vncpasswd COMMAND test_vncpasswd)

  add_custom_target(
    test_binaries
    DEPENDS ${UNIT_TEST_BINARIES}
    COMMENT "Building every unit test binary")
endif()

# ##############################################################################
# Coverage target

if(BUILD_TESTING AND HAVE_COVERAGE_TOOLS)

  set(COVERAGE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/coverage)
  set_property(
    DIRECTORY
    APPEND
    PROPERTY ADDITIONAL_CLEAN_FILES ${COVERAGE_OUTPUT_DIR})

  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")

    set(COVERAGE_INFO ${CMAKE_BINARY_DIR}/coverage.info)
    set(COVERAGE_INFO_CLEAN ${CMAKE_BINARY_DIR}/coverage.info.cleaned)
    set_property(
      DIRECTORY
      APPEND
      PROPERTY ADDITIONAL_CLEAN_FILES ${COVERAGE_INFO} ${COVERAGE_INFO_CLEAN})

    add_custom_target(
      coverage
      COMMAND ${LCOV_EXEC} --directory ${CMAKE_BINARY_DIR} --zerocounters
      COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${LCOV_EXEC} --directory ${CMAKE_BINARY_DIR} --capture --rc
              branch_coverage=1 --output-file ${COVERAGE_INFO}
      COMMAND
        ${LCOV_EXEC} --remove ${COVERAGE_INFO} '${CMAKE_SOURCE_DIR}/test/*' --rc
        branch_coverage=1 --output-file ${COVERAGE_INFO_CLEAN}
      COMMAND ${GENHTML_EXEC} --rc branch_coverage=1 -o ${COVERAGE_OUTPUT_DIR}
              ${COVERAGE_INFO_CLEAN}
      COMMAND ${LCOV_EXEC} --summary ${COVERAGE_INFO_CLEAN} --rc
              branch_coverage=1 --fail-under-lines 95
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS test_binaries
      COMMENT
        "Running tests and generating GCC coverage report in ${COVERAGE_OUTPUT_DIR}/index.html"
    )

  elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")

    set(PROFILE_DATA ${CMAKE_BINARY_DIR}/default.profdata)
    set_property(
      DIRECTORY
      APPEND
      PROPERTY ADDITIONAL_CLEAN_FILES ${PROFILE_DATA})

    # Extract first binary as the primary llvm-cov target; all others are passed
    # as repeated -object flags (required by llvm-cov syntax).
    list(GET UNIT_TEST_BINARIES 0 _llvm_cov_first_bin)
    set(_llvm_cov_object_args "")
    list(LENGTH UNIT_TEST_BINARIES _llvm_cov_num_bins)
    if(_llvm_cov_num_bins GREATER 1)
      list(SUBLIST UNIT_TEST_BINARIES 1 -1 _llvm_cov_remaining_bins)
      foreach(_llvm_cov_bin ${_llvm_cov_remaining_bins})
        list(APPEND _llvm_cov_object_args "-object" "${_llvm_cov_bin}")
      endforeach()
    endif()

    add_custom_target(
      coverage
      # Use %p so each test process writes its own profraw (avoids overwrite).
      COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=default-%p.profraw
              ${CMAKE_CTEST_COMMAND} --output-on-failure
      # Merge all per-process profraw files into one profdata.
      # Note: sh -c with shell glob is intentional — this project is Linux-only
      # (PAM module), and cmake -E does not support file globbing.  Tests must
      # run before this step so at least one default-*.profraw file exists.
      COMMAND
        sh -c
        "${LLVM_PROFDATA_EXEC} merge -sparse default-*.profraw -o ${PROFILE_DATA}"
      COMMAND
        ${LLVM_COV_EXEC} show ${_llvm_cov_first_bin}
        -instr-profile=${PROFILE_DATA} -format=html
        -output-dir=${COVERAGE_OUTPUT_DIR} ${_llvm_cov_object_args}
      COMMAND
        ${LLVM_COV_EXEC} report ${_llvm_cov_first_bin}
        -instr-profile=${PROFILE_DATA} -show-region-summary=false
        ${_llvm_cov_object_args}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS test_binaries
      COMMENT
        "Running tests and generating Clang coverage report in ${COVERAGE_OUTPUT_DIR}/index.html"
    )

  endif()

endif()
