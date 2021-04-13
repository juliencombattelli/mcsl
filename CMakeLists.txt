# CMake 3.15 needed for MSVC_RUNTIME_LIBRARY target property
cmake_minimum_required(VERSION 3.15)
project(mcsl)

option(MCSL_ENABLE_TESTING "Enable the build of the tests" ON)
option(MCSL_ENABLE_FUZZING "Enable the build of the fuzzy tests" OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(mcsl_string_view
    include/mcsl/common.h include/mcsl/string_view.h
    src/char_traits.h src/char_traits.c src/string_view.c
)
target_include_directories(mcsl_string_view PUBLIC include)

install(TARGETS mcsl_string_view)

add_library(mcsl::string_view ALIAS mcsl_string_view)

if(MCSL_ENABLE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()