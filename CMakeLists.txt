cmake_minimum_required(VERSION 3.0)
project(mensacard_test C)

set(CMAKE_C_STANDARD 99)

find_library(LIB_NFC nfc)
find_library(LIB_FREEFARE freefare)

if (NOT LIB_NFC)
    message(FATAL_ERROR "Cannot find libnfc")
endif()

if (NOT LIB_FREEFARE)
    message(FATAL_ERROR "Cannot find libfreefare")
endif()

add_executable(mensacard_test main.c)
target_link_libraries(mensacard_test ${LIB_NFC} ${LIB_FREEFARE})
