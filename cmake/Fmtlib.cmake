# FetchContent_MakeAvailable was added in CMake 3.14
cmake_minimum_required(VERSION 3.14)

include(FetchContent)

FetchContent_Declare(
    fmtlib
    GIT_REPOSITORY  https://github.com/fmtlib/fmt.git
    GIT_TAG         7.1.3
    GIT_SHALLOW     TRUE
)

FetchContent_MakeAvailable(fmtlib)