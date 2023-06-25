cmake_minimum_required (VERSION 3.12)

project (libaaa)

option(BUILD_SHARED_LIBS "Build a shared librarie" OFF)

if(${BUILD_SHARED_LIBS})
    add_compile_definitions(libaaa LIBAAA_SHARED)
endif()
add_compile_definitions(libaaa LIBAAA_BUILD)

add_library(libaaa src/libaaa.c)

target_include_directories(libaaa PUBLIC include)
