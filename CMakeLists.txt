cmake_minimum_required(VERSION 3.15)
project(Mcsl VERSION 0.1.0)

################################################################################
### Options definition
################################################################################

option(MCSL_ENABLE_TESTING "Enable the build of the tests" ON)
option(MCSL_ENABLE_FUZZING "Enable the build of the fuzzy tests" OFF)

################################################################################
### Global CMake variables configuration
################################################################################

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

################################################################################
### MCSL string_view library definition
################################################################################

add_library(mcsl_string_view
    include/mcsl/common.h include/mcsl/string_view.h
    src/char_traits.h src/char_traits.c src/string_view.c
)
set_target_properties(mcsl_string_view PROPERTIES
    EXPORT_NAME StringView
    PUBLIC_HEADER
        "include/mcsl/common.h;include/mcsl/string_view.h"
)
target_include_directories(mcsl_string_view
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
add_library(${PROJECT_NAME}::StringView ALIAS mcsl_string_view)

################################################################################
### Test execution
################################################################################

if(MCSL_ENABLE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

