cmake_minimum_required(VERSION 3.0)
project (lsarelayx)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(lsarelayx_static STATIC
    relaycontext.h relaycontext.cpp
    lsarelayx.cpp lsarelayx.hxx
    handle.hxx
    pipe.hxx pipe.cpp
    commands.h commands.cpp
    spnego.cpp spnego.hxx
    msv1_0.cpp msv1_0.hxx
    debug.cpp debug.hxx
    minhook/buffer.c
    minhook/hook.c
    minhook/trampoline.c
    minhook/hde/hde32.c
    minhook/hde/hde64.c)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")

target_include_directories(lsarelayx_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(lsarelayx SHARED dllmain.cpp lsarelayx.def)
target_link_libraries(lsarelayx lsarelayx_static -static-libgcc -static-libstdc++ -static ntdll_x64)
target_link_directories(lsarelayx PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(lsarelayx_runner main.cpp)
target_link_libraries(lsarelayx_runner lsarelayx_static ntdll_x64)
target_link_directories(lsarelayx_runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS lsarelayx RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX})


