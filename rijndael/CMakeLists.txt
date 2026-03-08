cmake_minimum_required(VERSION 3.20)
project(rijndael_lib)

# Настройки компилятора
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Просто создаем библиотеку Rijndael
add_library(rijndael_lib
        src/rijndael.cpp
)

# Заголовочные файлы
target_include_directories(rijndael_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Тесты Rijndael
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_rijndael.cpp)
    add_executable(rijndael_tests
            tests/test_rijndael.cpp
    )

    target_include_directories(rijndael_tests PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_link_libraries(rijndael_tests PRIVATE
            rijndael_lib
            gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(rijndael_tests)
endif()