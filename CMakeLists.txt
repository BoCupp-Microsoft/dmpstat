cmake_minimum_required(VERSION 3.24)
project(dmpstat VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# -----------------------------------------------------------------------------
# Microsoft.Debugging.DbgEng.Core redistributable (dbghelp.dll, symsrv.dll, ...)
#
# The system dbghelp.dll in C:\Windows\System32 is older and ships without
# symsrv.dll, which breaks symbol-server URLs in _NT_SYMBOL_PATH and lags
# behind on PDB format support. We redistribute a current dbghelp.dll plus
# its companions next to each .exe; Windows' DLL search order will pick them
# up in preference to the system copy.
#
# Set DBGENG_PACKAGE to either:
#   - a path to the Microsoft.Debugging.DbgEng.Core .nupkg file, or
#   - a path to an already-extracted package directory containing tools/<arch>/.
# -----------------------------------------------------------------------------
set(DBGENG_PACKAGE "$ENV{USERPROFILE}/Downloads/Microsoft.Debugging.DbgEng.Core.20260421.1615.0.nupkg"
    CACHE FILEPATH "Path to Microsoft.Debugging.DbgEng.Core .nupkg or its extracted directory")

set(_dbgeng_root "")
if(EXISTS "${DBGENG_PACKAGE}")
    if(IS_DIRECTORY "${DBGENG_PACKAGE}")
        set(_dbgeng_root "${DBGENG_PACKAGE}")
    else()
        # Treat as a .nupkg (zip). Extract once into the build tree.
        set(_dbgeng_root "${CMAKE_BINARY_DIR}/_deps/dbgeng")
        set(_dbgeng_stamp "${_dbgeng_root}/.extracted-from")
        set(_already "")
        if(EXISTS "${_dbgeng_stamp}")
            file(READ "${_dbgeng_stamp}" _already)
        endif()
        if(NOT "${_already}" STREQUAL "${DBGENG_PACKAGE}")
            message(STATUS "Extracting DbgEng package: ${DBGENG_PACKAGE}")
            file(REMOVE_RECURSE "${_dbgeng_root}")
            file(MAKE_DIRECTORY "${_dbgeng_root}")
            execute_process(
                COMMAND ${CMAKE_COMMAND} -E tar xf "${DBGENG_PACKAGE}"
                WORKING_DIRECTORY "${_dbgeng_root}"
                RESULT_VARIABLE _extract_rc
            )
            if(NOT _extract_rc EQUAL 0)
                message(FATAL_ERROR "Failed to extract DbgEng package (exit ${_extract_rc})")
            endif()
            file(WRITE "${_dbgeng_stamp}" "${DBGENG_PACKAGE}")
        endif()
    endif()
else()
    message(WARNING "DBGENG_PACKAGE not found at '${DBGENG_PACKAGE}'. "
        "valcount will fall back to the system dbghelp.dll. "
        "Set -DDBGENG_PACKAGE=<path-to-nupkg-or-extracted-dir> to enable redistribution.")
endif()

# Pick the matching arch subdir under tools/<arch>/.
if(_dbgeng_root)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        set(_dbgeng_arch arm64)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(_dbgeng_arch amd64)
    else()
        set(_dbgeng_arch x86)
    endif()
    set(_dbgeng_bin "${_dbgeng_root}/tools/${_dbgeng_arch}")
    if(NOT EXISTS "${_dbgeng_bin}/dbghelp.dll")
        message(WARNING "DbgEng arch directory missing dbghelp.dll: ${_dbgeng_bin}")
        set(_dbgeng_bin "")
    else()
        message(STATUS "DbgEng redistributables: ${_dbgeng_bin}")
    endif()
endif()

# Files to copy next to each consumer .exe. symsrv.yes is a zero-byte marker
# that suppresses symsrv's EULA prompt for non-interactive use.
set(_dbgeng_files
    dbghelp.dll
    symsrv.dll
    dbgcore.dll
    srcsrv.dll
    symsrv.yes
    msdia140.dll
)

# Helper: stage the DbgEng redistributables next to a target's output.
function(stage_dbgeng_redist target_name)
    if(NOT _dbgeng_bin)
        return()
    endif()
    set(_copy_cmds "")
    foreach(_f IN LISTS _dbgeng_files)
        set(_src "${_dbgeng_bin}/${_f}")
        if(EXISTS "${_src}")
            list(APPEND _copy_cmds
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_src}" "$<TARGET_FILE_DIR:${target_name}>/${_f}")
        endif()
    endforeach()
    if(_copy_cmds)
        add_custom_command(TARGET ${target_name} POST_BUILD ${_copy_cmds}
            COMMENT "Staging DbgEng redistributables next to ${target_name}")
    endif()
endfunction()

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

stage_dbgeng_redist(valcount)

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
    symbol_resolver.cpp
    symbol_resolver.hpp
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

stage_dbgeng_redist(valfind)
