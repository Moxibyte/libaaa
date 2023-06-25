cmake_minimum_required(VERSION 3.14)

add_subdirectory(../ libaaa)

project(libaaa_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)
# find_library(libaaa)

add_executable(libaaa_test 
    ./tests/pg_empty.cpp
    ./tests/pg_attribute.cpp
    ./tests/pg_x_attribute.cpp
)

target_link_libraries(libaaa_test PUBLIC GTest::gtest GTest::gtest_main GTest::gmock)
target_link_libraries(libaaa_test PUBLIC libaaa)
