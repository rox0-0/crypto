cmake_minimum_required(VERSION 3.20)
project(crypto_shit CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Включаем возможности для загрузки GTest если не найден
include(FetchContent)

# Если GTest не установлен системно, скачаем его
if(NOT GTEST_FOUND)
    message(STATUS "GTest not found, downloading...")
    FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    )
    set(INSTALL_GTEST OFF)
    FetchContent_MakeAvailable(googletest)
endif()

enable_testing()

# Добавляем поддиректории
add_subdirectory(rijndael)
add_subdirectory(des)
add_subdirectory(rsa)