include_directories(
    ${KAFL_EXAMPLES_DIR}/linux-user/libnyx_agent/src/
    ${KAFL_EXAMPLES_DIR}
)

add_library(
    nyx_agent_static STATIC 
    ${KAFL_EXAMPLES_DIR}/linux-user/libnyx_agent/src/nyx_agent.c
)
set_target_properties(
    nyx_agent_static PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wno-return-type"
    OUTPUT_NAME nyx_agent)

add_library(
    nyx_agent SHARED 
    ${KAFL_EXAMPLES_DIR}/linux-user/libnyx_agent/src/nyx_agent.c
)
set_target_properties(
    nyx_agent PROPERTIES
    COMPILE_FLAGS "-Wno-return-type"
    OUTPUT_NAME nyx_agent)

add_executable(vmcall ${KAFL_EXAMPLES_DIR}/linux-user/vmcall/src/vmcall.c)
target_link_libraries(vmcall nyx_agent_static)