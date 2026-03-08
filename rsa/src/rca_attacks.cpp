#include "rsa_attacks.h"
#include "rsa_crypto.h"
#include "math_utils.h"
#include <vector>
#include <tuple>

namespace crypto {
namespace attacks {

std::vector<crypto::types::BigInt> WienerAttack::compute_continued_fraction(const BigRational& value) {
    std::vector<BigInt> result;
    BigRational remainder = value;
    
    while (remainder != 0) {
        BigInt integer_part = numerator(remainder) / denominator(remainder);
        result.push_back(integer_part);
        remainder = remainder - integer_part;
        if (remainder != 0) {
            remainder = 1 / remainder;
        }
    }
    
    return result;
}

std::vector<crypto::types::BigRational> WienerAttack::compute_convergents(const std::vector<BigInt>& continued_fraction) {
    std::vector<BigRational> convergents;
    
    if (continued_fraction.empty()) {
        return convergents;
    }
    
    BigInt h0 = 0, h1 = 1;
    BigInt k0 = 1, k1 = 0;
    
    for (const auto& a : continued_fraction) {
        BigInt h2 = a * h1 + h0;
        BigInt k2 = a * k1 + k0;
        
        convergents.push_back(BigRational(h2, k2));
        
        h0 = h1;
        k0 = k1;
        h1 = h2;
        k1 = k2;
    }
    
    return convergents;
}

std::pair<bool, crypto::types::BigInt> WienerAttack::test_candidate(const BigInt& modulus,
                                                                   const BigInt& public_exponent,
                                                                   const BigRational& convergent) {
    if (denominator(convergent) == 0) {
        return {false, BigInt(0)};
    }
    
    BigInt k = denominator(convergent);
    BigInt d = numerator(convergent);
    
    if (k == 0 || d == 0) {
        return {false, BigInt(0)};
    }
    
    // Проверяем, что ed ≡ 1 (mod k)
    if ((public_exponent * d) % k != 1) {
        return {false, BigInt(0)};
    }
    
    // Вычисляем phi = (ed - 1) / k
    BigInt phi = (public_exponent * d - 1) / k;
    
    // Решаем квадратное уравнение: x^2 - (N - phi + 1)x + N = 0
    BigInt b = modulus - phi + 1;
    BigInt discriminant = b * b - 4 * modulus;
    
    if (discriminant < 0) {
        return {false, BigInt(0)};
    }
    
    // Проверяем, что дискриминант - полный квадрат
    BigInt root = sqrt(discriminant);
    if (root * root != discriminant) {
        return {false, BigInt(0)};
    }
    
    // Проверяем, что p и q - целые числа
    BigInt p = (b + root) / 2;
    BigInt q = (b - root) / 2;
    
    if (p * q == modulus) {
        return {true, d};
    }
    
    return {false, BigInt(0)};
}

std::tuple<bool, crypto::types::BigInt, crypto::types::BigInt, std::vector<crypto::types::BigRational>> 
WienerAttack::attack(const rsa::RSA& rsa_system) {
    auto public_key = rsa_system.get_public_key();
    BigInt N = public_key.mod;
    BigInt e = public_key.exp;
    
    // Вычисляем непрерывную дробь для e/N
    BigRational target(e, N);
    auto continued_fraction = compute_continued_fraction(target);
    
    // Вычисляем подходящие дроби
    auto convergents = compute_convergents(continued_fraction);
    
    // Проверяем каждую подходящую дробь
    for (const auto& convergent : convergents) {
        auto [success, d] = test_candidate(N, e, convergent);
        if (success) {
            BigInt phi = (e * d - 1) / denominator(convergent);
            return {true, d, phi, convergents};
        }
    }
    
    return {false, BigInt(0), BigInt(0), convergents};
}

void WienerAttack::generate_weak_key_pair(rsa::RSA& rsa_system) {
    rsa_system.generate_weak_key_pair();
}

} // namespace attacks
} // namespace crypto