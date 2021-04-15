include(${PROJECT_SOURCE_DIR}/cmake/Fmtlib.cmake)

add_library(string_view_fuzzy_test INTERFACE)
target_include_directories(string_view_fuzzy_test INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(string_view_fuzzy_test INTERFACE -fsanitize=fuzzer,undefined,address)
target_link_options(string_view_fuzzy_test INTERFACE -coverage -fsanitize=fuzzer,undefined,address)
target_link_libraries(string_view_fuzzy_test INTERFACE Mcsl::StringView fmt::fmt-header-only)

set(MCSL_FUZZY_TEST_MAX_DURATION "10" CACHE STRING "Maximal total time in seconds to run each fuzzy test")

function(add_fuzzy_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cpp)
    target_link_libraries(${TEST_NAME} PRIVATE string_view_fuzzy_test)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} -max_total_time=$CACHE{MCSL_FUZZY_TEST_MAX_DURATION})
endfunction()

add_fuzzy_test(sv_find_from_position)
add_fuzzy_test(sv_find)
add_fuzzy_test(sv_rfind_from_position)
add_fuzzy_test(sv_rfind)
