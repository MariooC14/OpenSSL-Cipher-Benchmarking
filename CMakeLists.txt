cmake_minimum_required(VERSION 4.1)
project(openssl_benchmark)

set(CMAKE_CXX_STANDARD 20)

find_library(LIBRT rt)
if(LIBRT)
    link_libraries(${LIBRT})
endif()

link_libraries(crypto)

add_executable(openssl_benchmark main.cpp
        openssl-benchmark.h
        openssl-benchmark.cpp)

add_executable(triple_des_benchmark triple-des-benchmark.cpp
        openssl-benchmark.h
        openssl-benchmark.cpp)
