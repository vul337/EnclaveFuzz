cmake_minimum_required(VERSION 3.16)
project(SGXSan)

set(LINUX_SGX_MINI "${CMAKE_CURRENT_SOURCE_DIR}/SGXSanRT/linux-sgx-mini/")

add_subdirectory(SGXSanPass)
add_subdirectory(SGXSanRT)
add_subdirectory(SGXFuzzerPass)
add_subdirectory(SGXFuzzerRT)

install(TARGETS
        SGXSanPass
        SGXSanRT
        SGXFuzzerPass
        SGXFuzzerRT
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64)

install(DIRECTORY
        ${LINUX_SGX_MINI}/common/inc/ DESTINATION include
        PATTERN common/inc/internal EXCLUDE)

install(FILES Tool/EdlParser.py
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        DESTINATION tool)

install(FILES Tool/sgx_edger8r
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        DESTINATION bin/x64)

install(FILES Tool/Enclave.export
        DESTINATION .)

install(FILES ${LINUX_SGX_MINI}/common/buildenv.mk
        DESTINATION .)
