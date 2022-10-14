if(NOT SGX_SDK)
    set(SGX_SDK "/opt/intel/sgxsdk")
endif()
message(STATUS "SGX_SDK: ${SGX_SDK}")

add_subdirectory(SGXSanRTApp)
add_subdirectory(SGXSanRTEnclave)
