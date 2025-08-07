cmake_minimum_required(VERSION 3.21...3.31)

project(materialbinloader)

if(NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
    message(FATAL_ERROR "Unsupported ABI")
endif()

set(CMAKE_CXX_STANDARD 23)

set(CPM_SOURCE_CACHE ${PROJECT_SOURCE_DIR}/cpm-cache CACHE PATH "")
include(cmake/CPM.cmake)

add_library(materialbinloader SHARED src/main.cpp)

CPMAddPackage("gh:BasedInc/libhat@0.6.0")
CPMAddPackage("gh:zyantific/zydis@4.1.1")
CPMAddPackage("gh:cursey/safetyhook@0.6.9")
target_link_libraries(materialbinloader PUBLIC libhat::libhat safetyhook::safetyhook)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(materialbinloader PRIVATE -flto)
    target_link_options(materialbinloader PRIVATE
        -flto -Wl,--version-script,${PROJECT_SOURCE_DIR}/map.txt -Wl,--no-undefined-version)
    set_target_properties(materialbinloader PROPERTIES
        LINK_DEPENDS ${PROJECT_SOURCE_DIR}/map.txt)
endif()

install(TARGETS materialbinloader LIBRARY DESTINATION mods)
