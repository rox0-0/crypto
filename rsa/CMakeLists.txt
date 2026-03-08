find_package(Boost REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GMP REQUIRED gmp)

add_library(libcrypto_math INTERFACE
        include/big_int.h
        include/rsa_crypto.h
        include/rsa_attacks.h
        include/primary_tests.h
        include/math_utils.h
        src/rca_attacks.cpp
        ../des/include/des_deal.h
        ../des/include/feistel_net.h
        ../des/src/feistel_net.cpp
        ../des/src/des_deal.cpp
        ../des/tests/test.cpp
        ../rijndael/include/GF_math.h
        ../rijndael/include/rijndael.h
        ../rijndael/src/rijndael.cpp
        ../rijndael/tests/test_rijndael.cpp
)
target_include_directories(libcrypto_math INTERFACE
        include
)
target_link_libraries(libcrypto_math INTERFACE
        Boost::boost
        gmp
)

add_library(librsa src/rsa.cpp
        include/big_int.h
        include/rsa_crypto.h
        include/rsa_attacks.h
        include/primary_tests.h
        include/math_utils.h
        src/rca_attacks.cpp
        ../rijndael/include/GF_math.h
        ../rijndael/include/rijndael.h
        ../rijndael/src/rijndael.cpp
        ../rijndael/tests/test_rijndael.cpp
)
target_link_libraries(librsa PUBLIC libcrypto_math)

add_executable(rsa_tests
        tests/test_rsa.cpp
        include/big_int.h
        include/rsa_crypto.h
        include/rsa_attacks.h
        include/primary_tests.h
        include/math_utils.h
        src/rca_attacks.cpp
        ../rijndael/include/GF_math.h
        ../rijndael/include/rijndael.h
        ../rijndael/src/rijndael.cpp
        ../rijndael/tests/test_rijndael.cpp
)

target_link_libraries(rsa_tests
        PRIVATE
        librsa
        GTest::gtest GTest::gtest_main
)

enable_testing()
add_test(NAME RSATests COMMAND rsa_tests)