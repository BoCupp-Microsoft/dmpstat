cmake_minimum_required(VERSION 3.24)
project(dmpstat VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add the executable
add_executable(valcount
    valcount.cpp
    mapped_view.cpp
    mapped_view.hpp
    pointer_counter.cpp
    pointer_counter.hpp
    progress.cpp
    progress.hpp
    symbol_resolver.cpp
    symbol_resolver.hpp
)

# Set compile definitions for Windows
target_compile_definitions(valcount PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
)

# Find dependencies provided via vcpkg
find_package(WIL CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

# Link required Windows libraries
target_link_libraries(valcount PRIVATE
    dbghelp
    WIL::WIL
    CLI11::CLI11
)

# Set compiler-specific options
target_compile_options(valcount PRIVATE 
    /W4      # Warning level 4
    /MP      # Multi-processor compilation
)

# Set subsystem to console
set_target_properties(valcount PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:CONSOLE"
)

# Print build information
message(STATUS "Building Windows Dump File Analyzer")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")

# valfind: locate occurrences of a 64-bit value in a dump file.
add_executable(valfind
    valfind.cpp
    mapped_view.cpp
    mapped_view.hpp
    progress.cpp
    progress.hpp
)

target_compile_definitions(valfind PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    NOMINMAX
)

target_link_libraries(valfind PRIVATE
    dbghelp
    WIL::WIL
    CLI11::CLI11
)

target_compile_options(valfind PRIVATE
    /W4
    /MP
)

set_target_properties(valfind PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:CONSOLE"
)
