cmake_minimum_required(VERSION 3.26)
project(MalDev23)

set(CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++ -static-libgcc")

add_executable(MalDev23
        day-06/lab-09/main.cpp)
