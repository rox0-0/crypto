#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include "math_utils.h"
#include "rsa_attacks.h"
#include "big_int.h"
#include <memory>
#include <vector>

namespace crypto {
    namespace rsa {

        class RSA {
        public:
            enum struct PrimalityTestType {
                FERMAT,
                SOLOVAY_STRASSEN,
                MILLER_RABIN,
            };

            struct Key {
                BigInt exp;
                BigInt mod;
            };

            RSA(RSA &) = delete;
            RSA(RSA &&) = default;
            RSA &operator=(RSA &) = delete;
            RSA &operator=(RSA &&) = default;

        private:
            class KeyGen {
            public:
                KeyGen(PrimalityTestType test_type, double min_probability, size_t bit_len);

                struct KeyPairRSA {
                    Key publicKey;
                    Key privateKey;
                };

                [[nodiscard]] KeyPairRSA generate_key_pair() const;
                [[nodiscard]] KeyPairRSA generate_weak_key_pair() const;

            private:
                PrimalityTestType _test_type;
                double _min_probability;
                size_t _prime_bit_len;

                [[nodiscard]] std::pair<BigInt, BigInt> generate_prime_pair() const;
                [[nodiscard]] BigInt generate_prime_candidate() const;
            };

        public:
            RSA(PrimalityTestType test_type, double min_probability, size_t prime_bit_len);

            [[nodiscard]] BigInt encrypt(const BigInt &data) const;
            [[nodiscard]] BigInt decrypt(const BigInt &data) const;
            
            void generate_key_pair();
            void generate_weak_key_pair();

            [[nodiscard]] Key get_public_key() const;
            [[nodiscard]] Key get_priv_key() const { return _key_pair.privateKey; }

            void set_public_key(Key pub_key);

        private:
            std::unique_ptr<KeyGen> _key_generator;
            KeyGen::KeyPairRSA _key_pair;

            // Используем полное имя с пространством имен
            friend class crypto::attacks::WienerAttack;
        };

    } // namespace rsa
} // namespace crypto

#endif // CRYPTO_RSA_H