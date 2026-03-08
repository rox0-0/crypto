#include "rsa_crypto.h"
#include "primary_tests.h"
#include <bitset>
#include <future>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <memory>

namespace crypto {
namespace rsa {

RSA::RSA(PrimalityTestType test_type, double min_probability, size_t prime_bit_len)
    : _key_generator(std::make_unique<KeyGen>(test_type, min_probability, prime_bit_len)) {}

BigInt RSA::encrypt(const BigInt &data) const {
    if (data >= _key_pair.publicKey.mod)
        throw std::invalid_argument("data >= mod");
    if (data == BigInt(1) || math::compute_gcd(_key_pair.publicKey.mod, data) != BigInt(1)) {
        throw std::invalid_argument("gcd(data, mod) != 1 or data == 1");
    }

    return math::modular_power(data, _key_pair.publicKey.exp, _key_pair.publicKey.mod);
}

BigInt RSA::decrypt(const BigInt &data) const {
    if (data >= _key_pair.privateKey.mod)
        throw std::invalid_argument("data >= mod");
    return math::modular_power(data, _key_pair.privateKey.exp, _key_pair.privateKey.mod);
}

void RSA::generate_key_pair() {
    _key_pair = _key_generator->generate_key_pair();
}

void RSA::generate_weak_key_pair() {
    _key_pair = _key_generator->generate_weak_key_pair();
}

RSA::Key RSA::get_public_key() const {
    return _key_pair.publicKey;
}

void RSA::set_public_key(Key pub_key) {
    _key_pair.publicKey = std::move(pub_key);
}

// KeyGen implementation
RSA::KeyGen::KeyPairRSA RSA::KeyGen::generate_key_pair() const {
    static const BigInt exponents[] = {BigInt(17), BigInt(257), BigInt(65537)};

    auto [p, q] = generate_prime_pair();
    BigInt N = p * q;
    BigInt phi = (p - BigInt(1)) * (q - BigInt(1));
    BigInt encrypt_exp{0};
    BigInt decrypt_exp{0};

    for (const auto &e: exponents) {
        if (math::compute_gcd(e, phi) == BigInt(1)) {
            BigInt inverse = std::get<1>(math::extended_gcd(e, phi));
            decrypt_exp = (inverse % phi + phi) % phi;
            if (boost::multiprecision::pow(decrypt_exp, 4) * 81 >= N) {
                encrypt_exp = e;
                break;
            }
        }
    }

    if (!encrypt_exp) {
        while (true) {
            namespace rnd = boost::random;
            static rnd::mt19937 gen(static_cast<unsigned int>(std::time(nullptr)));
            const rnd::uniform_int_distribution<BigInt> dist(BigInt(3), phi - BigInt(1));
            BigInt e = dist(gen) | BigInt(1);
            BigInt gcd_val = math::compute_gcd(e, phi);
            if (gcd_val == BigInt(1)) {
                BigInt inverse = std::get<1>(math::extended_gcd(e, phi));
                decrypt_exp = (inverse % phi + phi) % phi;
                if (boost::multiprecision::pow(decrypt_exp, 4) * 81 >= N) {
                    encrypt_exp = e;
                    break;
                }
            }
        }
    }

    return KeyPairRSA{
        {std::move(encrypt_exp), N},
        {std::move(decrypt_exp), std::move(N)}
    };
}

RSA::KeyGen::KeyPairRSA RSA::KeyGen::generate_weak_key_pair() const {
    static boost::random::mt19937 gen(static_cast<unsigned int>(std::time(nullptr)));
    auto [p, q] = generate_prime_pair();
    BigInt N = p * q;
    BigInt phi = (p - BigInt(1)) * (q - BigInt(1));
    BigInt decrypt_exp{0};
    BigInt encrypt_exp{0};

    const boost::random::uniform_int_distribution dist(BigInt(3), mp::sqrt(mp::sqrt(N)) / 3);

    while (true) {
        decrypt_exp = dist(gen);
        if (math::compute_gcd(decrypt_exp, phi) != BigInt(1)) continue;
        auto inverse = std::get<1>(math::extended_gcd(decrypt_exp, phi));
        encrypt_exp = (inverse % phi + phi) % phi;
        if (math::compute_gcd(encrypt_exp, phi) == BigInt(1)) {
            break;
        }
    }

    return KeyPairRSA{
        {std::move(encrypt_exp), N},
        {std::move(decrypt_exp), std::move(N)}
    };
}

RSA::KeyGen::KeyGen(PrimalityTestType test_type, double min_probability, size_t prime_bit_len)
    : _test_type{test_type},
      _min_probability{min_probability},
      _prime_bit_len{prime_bit_len} {}

BigInt RSA::KeyGen::generate_prime_candidate() const {
    static boost::random::mt19937 gen(static_cast<unsigned int>(std::time(nullptr)));
    BigInt l_border = mp::pow(BigInt(2), _prime_bit_len - 1);
    BigInt r_border = (l_border * BigInt(2)) - BigInt(1);
    const boost::random::uniform_int_distribution dist(std::move(l_border), std::move(r_border));
    return dist(gen) | BigInt(1);
}

std::pair<BigInt, BigInt> RSA::KeyGen::generate_prime_pair() const {
    const BigInt set_mask = (BigInt(0xFF) << (_prime_bit_len - 8));
    const BigInt clear_mask = ((BigInt(1) << _prime_bit_len) - BigInt(1)) ^ (BigInt(0xFF) << (_prime_bit_len - 8 - 1));

    BigInt p, q;
    std::unique_ptr<primary::IProbabilisticPrimalityTest> test;
    switch (_test_type) {
        case PrimalityTestType::FERMAT:
            test = std::make_unique<primary::FermatTest>();
            break;
        case PrimalityTestType::SOLOVAY_STRASSEN:
            test = std::make_unique<primary::SolovayStrassenTest>();
            break;
        case PrimalityTestType::MILLER_RABIN:
            test = std::make_unique<primary::MillerRabinTest>();
            break;
    }

    auto func = [this, &test, &set_mask]() {
        while (true) {
            BigInt p_candidate = generate_prime_candidate();
            p_candidate |= set_mask;
            if (test->is_primary(p_candidate, _min_probability)) {
                return p_candidate;
            }
        }
    };

    auto p_fut = std::async(std::launch::async, func);

    while (true) {
        q = generate_prime_candidate();
        q &= clear_mask;
        if (test->is_primary(q, _min_probability)) break;
    }

    return {p_fut.get(), q};
}

} // namespace rsa
} // namespace crypto