# Modern C String Library

![build status](https://github.com/juliencombattelli/mcsl/workflows/Build%20&%20Tests/badge.svg)
[![codecov](https://codecov.io/gh/juliencombattelli/mcsl/branch/master/graph/badge.svg?token=0L5KEeuCMn)](https://codecov.io/gh/juliencombattelli/mcsl)

MCSL is a string management library aiming to provide a better interface than the standard C string
utilities (strtok, strpbrk to name a few).

It is written in C99 and does not have any external dependencies except from the standard library (a
compile flag will be available soon to use homemade alternatives to standard functions like memcpy).

It is heavily based on std::string and std::string_view from C++, and each of the supported
operations shall have the same exact behavior as its C++ counterpart.

## Features

MCSL provides the following features:
- **mcsl_sv** — A read-only view on a character string based on the std::string_view class from C++20
- **mcsl_str** — A allocator-aware character string based on the std::string class from C++23
- **fuzzy tests** — Fuzzy tested and sanitized alongside the C++ equivalent to ensure the behavior is the same

MCSL supports the following platforms:
- **Linux** — Tested with GCC and Clang/libstdc++
- **MacOS** — Tested with Clang/libc++
- **Windows** — Tested with MSVC and MinGW

## Building

### Requirements

This project requires CMake 3.15+ and a C99 compliant compiler to build the source code.
Additionally, a C++17 compliant compiler is needed to build the tests.
To build the fuzzy tests, Clang 12+ is mandatory.

### Build options

- **MCSL_ENABLE_TESTING** — Build of the tests (default: ON)
- **MCSL_ENABLE_FUZZING** — Build of the fuzzy tests (default: OFF, needs MCSL_ENABLE_TESTING=ON)
- **MCSL_ENABLE_COVERAGE** — Build with code coverage analysis (default: OFF, needs MCSL_ENABLE_TESTING=ON)

### Build procedure

```bash
# Configure the project with all tests enabled
cmake -S path-to-mcsl -B mcsl-build -DCMAKE_BUILD_TYPE=Debug -DMCSL_ENABLE_FUZZING=ON
# Build MCSL
cmake --build mcsl-build --parallel 4
# Run tests
cmake --build mcsl-build --target test
# Run coverage report generation
cmake --build mcsl-build --target coverage
```

## Contributing

If you want to get involved and suggest some additional features, signal a bug or submit a patch, please create
a pull request or open an issue on the [MCSL Github repository](https://github.com/juliencombattelli/mcsl).
