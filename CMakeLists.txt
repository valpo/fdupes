cmake_minimum_required(VERSION 2.8)

project(fdupes)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread")

find_package(Boost REQUIRED COMPONENTS iostreams)

list(APPEND FDUPES_SOURCES fdupes.cpp hash_64a.c)
add_executable(fdupes ${FDUPES_SOURCES})
target_link_libraries(fdupes ${Boost_LIBRARIES})
