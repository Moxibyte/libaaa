cmake_minimum_required(VERSION 3.14)
project(libaaa_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(gtest REQUIRED)

add_executable(libaaa_test ./tests/Example.cpp)
target_link_libraries(libaaa_test PUBLIC GTest::gtest GTest::gtest_main)
