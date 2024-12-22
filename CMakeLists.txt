cmake_minimum_required(VERSION 3.15)

project(materialbinloader)

set(CMAKE_CXX_STANDARD 23)

include(FetchContent)

FetchContent_Declare(libhat
        GIT_REPOSITORY https://github.com/BasedInc/libhat.git
        GIT_TAG 5cf79adf86152233371b43adab5a0f9db6daa4e7
        EXCLUDE_FROM_ALL)

FetchContent_Declare(safetyhook
        GIT_REPOSITORY https://github.com/cursey/safetyhook.git
        GIT_TAG de83823750b604c83b93bc80683b02978d3ae589
        EXCLUDE_FROM_ALL)

set(SAFETYHOOK_FETCH_ZYDIS ON)

FetchContent_MakeAvailable(libhat safetyhook)

add_library(materialbinloader SHARED src/main.cpp)

target_link_libraries(materialbinloader PUBLIC libhat safetyhook::safetyhook)

install(TARGETS materialbinloader LIBRARY DESTINATION mods)
