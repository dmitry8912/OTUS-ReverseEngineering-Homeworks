cmake_minimum_required(VERSION 4.0)
project(pe_loader_c C)

set(CMAKE_C_STANDARD 11)

add_executable(pe_loader_c main.c
        util/parser.c)
