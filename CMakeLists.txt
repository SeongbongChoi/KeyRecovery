cmake_minimum_required(VERSION 3.12)
project(KeyRecovery LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

find_package(OpenSSL REQUIRED)

add_executable(krp
    src/main.cpp
    src/ours.cpp
    src/hjky95.cpp
    src/party.cpp
    src/primitive.cpp
)
target_include_directories(krp PRIVATE include)
target_link_libraries(krp PRIVATE OpenSSL::Crypto)
target_compile_options(krp PRIVATE -Wall -Wextra -Wpedantic)
