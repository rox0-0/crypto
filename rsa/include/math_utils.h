#ifndef CRYPTO_MATH_UTILS_H
#define CRYPTO_MATH_UTILS_H

#include "big_int.h"
#include <tuple>
#include <stdexcept>

namespace crypto {
namespace math {

inline types::BigInt modular_power(types::BigInt base, types::BigInt exponent, const types::BigInt& modulus) {
    if (exponent < 0) {
        throw std::invalid_argument("Negative exponent not supported");
    }
    
    base = (base % modulus + modulus) % modulus;
    types::BigInt result = 1;
    
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    return result;
}

inline types::BigInt compute_gcd(const types::BigInt& num1, const types::BigInt& num2) {
    types::BigInt a = boost::multiprecision::abs(num1);
    types::BigInt b = boost::multiprecision::abs(num2);

    while (b != 0) {
        types::BigInt remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

inline std::tuple<types::BigInt, types::BigInt, types::BigInt> extended_gcd(const types::BigInt& a, const types::BigInt& b) {
    if (a == 0) {
        return {b, 0, 1};
    }
    
    auto [gcd_val, x1, y1] = extended_gcd(b % a, a);
    types::BigInt x = y1 - (b / a) * x1;
    types::BigInt y = x1;
    
    return {gcd_val, x, y};
}

inline int jacobi_symbol(types::BigInt numerator, types::BigInt denominator) {
    if (denominator < 2) {
        throw std::invalid_argument("Denominator must be >= 2");
    }
    if ((denominator & 1) == 0) {
        throw std::invalid_argument("Denominator must be odd");
    }
    
    if (compute_gcd(numerator, denominator) != 1) {
        return 0;
    }
    
    int result_sign = 1;
    
    if (numerator < 0) {
        numerator = -numerator;
        if (denominator % 4 == 3) {
            result_sign *= -1;
        }
    }
    
    while (numerator != 0) {
        unsigned int power_of_two = 0;
        while ((numerator & 1) == 0) {
            power_of_two++;
            numerator >>= 1;
        }
        
        if ((power_of_two & 1) == 1) {
            types::BigInt mod8 = denominator % 8;
            if (mod8 == 3 || mod8 == 5) {
                result_sign *= -1;
            }
        }
        
        if (numerator % 4 == 3 && denominator % 4 == 3) {
            result_sign *= -1;
        }
        
        types::BigInt temp = denominator % numerator;
        denominator = numerator;
        numerator = temp;
    }
    
    return result_sign;
}

inline int legendre_symbol(const types::BigInt& a, const types::BigInt& p) {
    return jacobi_symbol(a, p);
}

} // namespace math
} // namespace crypto

#endif // CRYPTO_MATH_UTILS_H