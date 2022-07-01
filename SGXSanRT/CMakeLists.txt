# Locate SGX Directory
set(SGX_DIR "$ENV{SGX_DIR}")
if(NOT SGX_DIR)
    set(SGX_DIR "/opt/intel/sgxsdk")
endif()
message(STATUS "SGX_DIR: ${SGX_DIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC")

include_directories(${SGX_DIR}/include)
add_library(SGXSanRT STATIC Malloc.cpp Poison.cpp PoisonCheck.cpp SGXSanRT.cpp ArgShadow.cpp OutAddrWhitelist.cpp Sticker.cpp sdk/src/spinlock.c)