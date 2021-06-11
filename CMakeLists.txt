cmake_minimum_required(VERSION 3.15)
project(Mcsl VERSION 0.1.0)

################################################################################
### Options definition
################################################################################
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(MCSL_ENABLE_TESTING_IF_STANDALONE ON)
else()
    set(MCSL_ENABLE_TESTING_IF_STANDALONE OFF)
endif()

option(MCSL_ENABLE_TESTING "Enable the build of the tests" ${MCSL_ENABLE_TESTING_IF_STANDALONE})
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

add_library(mcsl_string_view)
target_sources(mcsl_string_view
    PRIVATE
        include/mcsl/common.h
        include/mcsl/string_view.h
        src/string_view.c
        src/char_traits.h
        src/char_traits.c
)
set_target_properties(mcsl_string_view
    PROPERTIES
        EXPORT_NAME StringView
        PUBLIC_HEADER "include/mcsl/common.h;include/mcsl/string_view.h"
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

################################################################################
### Package config file generation and installation
################################################################################

include(GNUInstallDirs)

set(ConfigPackageLocation ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

# Generate CMake package config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/${PROJECT_NAME}Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION ${ConfigPackageLocation}
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install the package config and version files
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    DESTINATION ${ConfigPackageLocation}
)

################################################################################
### Mcsl::StringView installation
################################################################################

# Install the library and headers
install(
    TARGETS mcsl_string_view
    EXPORT ${PROJECT_NAME}StringViewTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mcsl
)

# Install the target file
install(
    EXPORT ${PROJECT_NAME}StringViewTargets
    FILE ${PROJECT_NAME}StringViewTargets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${ConfigPackageLocation}
)
