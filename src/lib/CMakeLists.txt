# dmpstat_lib: common code shared across tools.
add_library(dmpstat_lib STATIC
    dump_memory.cpp
    dump_memory.hpp
    mapped_view.cpp
    mapped_view.hpp
    progress.cpp
    progress.hpp
    symbol_resolver.cpp
    symbol_resolver.hpp
)

# symbol_downloader.{cpp,hpp} and token_fetcher.{cpp,hpp} are work-in-progress
# stubs that are not yet wired into any tool. They are kept in the lib folder
# but excluded from the build until their interfaces stabilize.

target_include_directories(dmpstat_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(dmpstat_lib PUBLIC
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    NOMINMAX
)

target_link_libraries(dmpstat_lib PUBLIC
    dbghelp
    WIL::WIL
)

target_compile_options(dmpstat_lib PRIVATE
    /W4
    /MP
)
