cmake_minimum_required(VERSION 3.24)
project(dmpstat VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add the executable
add_executable(valcount
    command_line.cpp
    command_line.hpp
    valcount.cpp
    mapped_file.cpp
    mapped_file.hpp
    pointer_counter.cpp
    pointer_counter.hpp
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

# Link required Windows libraries
target_link_libraries(valcount PRIVATE
    dbghelp
    WIL::WIL
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
