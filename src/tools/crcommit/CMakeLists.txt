add_executable(crcommit
    crcommit.cpp
    oilpan_heap.cpp
    oilpan_heap.hpp
    oilpan_objects.cpp
    oilpan_objects.hpp
    v8_heap.cpp
    v8_heap.hpp
)

dmpstat_configure_tool(crcommit)
