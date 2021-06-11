include(${PROJECT_SOURCE_DIR}/cmake/GoogleTest.cmake)

add_executable(mcsl_utests string_view_tests.cpp)
target_link_libraries(mcsl_utests PRIVATE Mcsl::StringView gtest)
add_test(NAME mcsl_utests COMMAND mcsl_utests)