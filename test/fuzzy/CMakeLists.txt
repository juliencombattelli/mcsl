include(${PROJECT_SOURCE_DIR}/cmake/Fmtlib.cmake)

################################################################################
### Header-only helper library for MCSL fuzzy tests
################################################################################

add_library(mcsl_string_view_fuzzy_test INTERFACE)
target_include_directories(mcsl_string_view_fuzzy_test 
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_options(mcsl_string_view_fuzzy_test
    INTERFACE
        -fsanitize=fuzzer,undefined,address
)
target_link_options(mcsl_string_view_fuzzy_test
    INTERFACE
        -coverage
        -fsanitize=fuzzer,undefined,address
)
target_link_libraries(mcsl_string_view_fuzzy_test
    INTERFACE
        Mcsl::StringView
        fmt::fmt-header-only
)

################################################################################
### Configuration options
################################################################################

set(MCSL_FUZZY_TEST_MAX_DURATION "10" CACHE STRING 
    "Maximal total time in seconds to run each fuzzy test"
)

################################################################################
### Helper function to define fuzzy test
################################################################################

function(mcsl_add_fuzzy_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cpp)
    target_link_libraries(${TEST_NAME}
        PRIVATE
            mcsl_string_view_fuzzy_test
    )
    add_test(
        NAME ${TEST_NAME}
        COMMAND ${TEST_NAME} -max_total_time=$CACHE{MCSL_FUZZY_TEST_MAX_DURATION}
    )
endfunction()

################################################################################
### Fuzzy tests list
################################################################################

mcsl_add_fuzzy_test(mcsl_sv_find_from_position)
mcsl_add_fuzzy_test(mcsl_sv_find)
mcsl_add_fuzzy_test(mcsl_sv_rfind_from_position)
mcsl_add_fuzzy_test(mcsl_sv_rfind)
