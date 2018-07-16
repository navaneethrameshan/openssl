cmake_minimum_required(VERSION 3.3)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-all -std=c++14 -Wall -Wno-unknown-pragmas")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "../")

include_directories(/usr/local/include)
link_directories(
        /usr/local/lib
        lib/macos/x86_64)

include_directories(include)
include_directories(crypto)
include_directories(crypto/include)
include_directories(engines)

if (${APPLE})
    link_libraries(
            bfd
            dl)
else()
    link_libraries(
            crypto
            ssl
            pthread
            dl)
endif()


if (${APPLE})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -DBACKWARD_SYSTEM_DARWIN -fno-pie -fpermissive -g -fno-inline -O0")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive -g -fno-inline -O0")
endif()

add_executable(custom_generator custom_generator.cpp)