include(${CMAKE_SOURCE_DIR}/cmake/GoogleTest.cmake)

add_executable(utests string_view_tests.cpp)
target_link_libraries(utests PRIVATE Mcsl::StringView gtest)
add_test(NAME utests COMMAND utests)