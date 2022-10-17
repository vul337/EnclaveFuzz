cmake_minimum_required(VERSION 3.16)
project(SGXSan)

add_subdirectory(SGXSanPass)
add_subdirectory(SGXSanRT)
add_subdirectory(SGXFuzzerPass)
add_subdirectory(SGXFuzzerRT)

install(TARGETS
        SGXSanPass
        SGXSanRTApp
        SGXSanRTEnclave
        SGXFuzzerPass
        SGXFuzzerRT
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64)

install(FILES SGXSanRT/SGXSanRTEnclave/SGXSanRTEnclave.edl
        DESTINATION include)

install(FILES Tool/sgx_edger8r
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        DESTINATION bin/x64)
