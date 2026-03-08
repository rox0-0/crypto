#ifndef CRYPTO_RSA_ATTACKS_H
#define CRYPTO_RSA_ATTACKS_H

#include "big_int.h"
#include <vector>
using namespace crypto::types;
namespace crypto {
    namespace rsa {
        class RSA;  // Forward declaration
    }

    namespace attacks {

        class WienerAttack final {
            static std::vector<BigInt> compute_continued_fraction(const BigRational& value);
            static std::vector<BigRational> compute_convergents(const std::vector<BigInt>& continued_fraction);
            static std::pair<bool, BigInt> test_candidate(const BigInt& modulus,
                                                         const BigInt& public_exponent,
                                                         const BigRational& convergent);

        public:
            // Используем полное имя с пространством имен
            static std::tuple<bool, BigInt, BigInt, std::vector<BigRational>>
            attack(const rsa::RSA& rsa_system);

            static void generate_weak_key_pair(rsa::RSA& rsa_system);
        };

    } // namespace attacks
} // namespace crypto

#endif // CRYPTO_RSA_ATTACKS_H