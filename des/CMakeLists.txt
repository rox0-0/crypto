cmake_minimum_required(VERSION 3.20)
project(crypto_des)

# Настройки компилятора
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Вместо find_package используем FetchContent для GTest
include(FetchContent)

FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
)

# Устанавливаем параметр для предотвращения установки
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

# Теперь GTest доступен как googletest
message(STATUS "Using fetched GTest")

# Основная библиотека с алгоритмами
add_library(crypto_des
        src/des_deal.cpp
        src/feistel_net.cpp
        src/paddings.cpp
        ../rijndael/include/GF_math.h
        ../rijndael/include/rijndael.h
        ../rijndael/src/rijndael.cpp
        ../rijndael/tests/test_rijndael.cpp
)

# Заголовочные файлы
target_include_directories(crypto_des
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Общий тест для всех алгоритмов
add_executable(crypto_tests
        tests/test.cpp
        ../rijndael/include/GF_math.h
        ../rijndael/include/rijndael.h
        ../rijndael/src/rijndael.cpp
        ../rijndael/tests/test_rijndael.cpp
)

target_include_directories(crypto_tests
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Используем googletest вместо GTest
target_link_libraries(crypto_tests
        PRIVATE
        crypto_des
        gtest_main
)

# Для удобства создаем алиасы
add_executable(des_tests ALIAS crypto_tests)
add_executable(triple_des_tests ALIAS crypto_tests)
add_executable(deal_tests ALIAS crypto_tests)

# Дополнительная цель для запуска всех тестов
add_custom_target(run_tests
        COMMAND ./crypto_tests
        DEPENDS crypto_tests
        COMMENT "Running all crypto tests"
)

# Теперь можно включить тесты
include(GoogleTest)
gtest_discover_tests(crypto_tests)