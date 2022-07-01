cmake_minimum_required(VERSION 3.16)
project(SGXSan)

add_subdirectory(SGXSanPass)
add_subdirectory(SGXSanRT)

install(TARGETS SGXSanPass LIBRARY DESTINATION lib)
install(TARGETS SGXSanRT LIBRARY DESTINATION lib)
# install(DIRECTORY SDKLib/ DESTINATION lib)
install(DIRECTORY SGXSanRT/sdk/inc/ DESTINATION include)
install(FILES PyScript/EdlParser.py
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        DESTINATION tool)