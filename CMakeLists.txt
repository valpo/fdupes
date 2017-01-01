cmake_minimum_required(VERSION 2.8)

project(fdupes)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

list(APPEND FDUPES_SOURCES fdupes.cpp md5/md5.c hash_64a.c)
add_executable(fdupes ${FDUPES_SOURCES})
