# Helper to apply common settings to each tool executable.
function(dmpstat_configure_tool target_name)
    target_link_libraries(${target_name} PRIVATE
        dmpstat_lib
        CLI11::CLI11
    )
    target_compile_options(${target_name} PRIVATE
        /W4
        /MP
    )
    set_target_properties(${target_name} PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
    stage_dbgeng_redist(${target_name})
endfunction()

add_subdirectory(valcount)
add_subdirectory(valfind)
add_subdirectory(segments)
add_subdirectory(crcommit)
