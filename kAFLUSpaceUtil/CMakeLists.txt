include_directories(include)

add_library(
    nyx_agent_static STATIC 
    src/nyx_agent.c)
set_target_properties(
    nyx_agent_static PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wno-return-type"
    OUTPUT_NAME nyx_agent)

add_library(
    nyx_agent SHARED 
    src/nyx_agent.c)
set_target_properties(
    nyx_agent PROPERTIES
    COMPILE_FLAGS "-Wno-return-type"
    OUTPUT_NAME nyx_agent)

add_executable(vmcall src/vmcall.c)
target_link_libraries(vmcall nyx_agent_static)