cmake_minimum_required(VERSION 3.15)

project(materialbinloader)

set(CMAKE_CXX_STANDARD 23)

include(FetchContent)

FetchContent_Declare(safetyhook
        GIT_REPOSITORY https://github.com/cursey/safetyhook.git
        GIT_TAG b046e123dc69821f2c375161e0adef3c6d9c9db4
        EXCLUDE_FROM_ALL)

set(SAFETYHOOK_FETCH_ZYDIS ON)

FetchContent_MakeAvailable(safetyhook)

add_library(materialbinloader SHARED src/main.cpp src/sig.cpp)

target_link_libraries(materialbinloader PUBLIC safetyhook::safetyhook)

install(TARGETS materialbinloader LIBRARY DESTINATION mods)
