cmake_minimum_required(VERSION 2.8)

project(fdupes)

list(APPEND FDUPES_SOURCES fdupes.cpp md5/md5.c)
add_executable(fdupes ${FDUPES_SOURCES})
