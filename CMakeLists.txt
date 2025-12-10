cmake_minimum_required(VERSION 3.15)
project(DmpAnalyzer VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add the executable
add_executable(dmp_analyzer dmp_analyzer.cpp)

# Set compile definitions for Windows
target_compile_definitions(dmp_analyzer PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
)

# Link required Windows libraries
target_link_libraries(dmp_analyzer 
    dbghelp
)

# Set compiler-specific options
if(MSVC)
    target_compile_options(dmp_analyzer PRIVATE 
        /W4      # Warning level 4
        /MP      # Multi-processor compilation
    )
    
    # Set subsystem to console
    set_target_properties(dmp_analyzer PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(dmp_analyzer PRIVATE 
        -Wall 
        -Wextra 
        -pedantic
    )
endif()

# Install target (optional)
install(TARGETS dmp_analyzer 
    RUNTIME DESTINATION bin
)

# Print build information
message(STATUS "Building Windows Dump File Analyzer")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
