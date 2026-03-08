//
// Created by lausniko on 14.01.2026.
//

#ifndef GF_MATH_H
#define GF_MATH_H

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <tuple>
#include <bit>
#include <algorithm>

namespace crypto::gf {
    constexpr uint8_t add(uint8_t a, uint8_t b) {
        return a ^ b;
    }

    constexpr int degree(uint16_t a) {
        if (a == 0) return -1;
        return 15 - std::countl_zero(a);
    }

    constexpr uint8_t inverse(uint8_t a, uint8_t mod_poly) {
        if (a == 0) throw std::invalid_argument("Zero has no inverse");

        uint16_t t0 = 0, t1 = 1;
        uint16_t r0 = mod_poly | 0x100;
        uint16_t r1 = a;

        while (r1 != 0) {
            int deg_r0 = degree(r0);
            int deg_r1 = degree(r1);

            if (deg_r0 < deg_r1) {
                std::swap(r0, r1);
                std::swap(t0, t1);
                continue;
            }

            auto shift = deg_r0 - deg_r1;
            uint16_t t_temp = t0 ^ (t1 << shift);
            uint16_t r_temp = r0 ^ (r1 << shift);
            t0 = t1;
            t1 = t_temp;
            r0 = r1;
            r1 = r_temp;
            if (r0 == 1) break;
        }

        if (r0 != 1) {
            throw std::runtime_error("No inverse exists");
        }

        return static_cast<uint8_t>(t0);
    }

    constexpr std::pair<uint16_t, uint16_t> divide(uint16_t dividend, uint16_t divisor) {
        if (divisor == 0)
            throw std::invalid_argument("Divide by zero");

        uint16_t quotient = 0;
        uint16_t remainder = dividend;
        int deg_divisor = degree(divisor);
        int deg_remainder = degree(remainder);

        while (deg_remainder >= deg_divisor) {
            int shift = deg_remainder - deg_divisor;
            quotient |= (1 << shift);
            remainder ^= (divisor << shift);
            deg_remainder = degree(remainder);
        }

        return {quotient, remainder};
    }

    constexpr bool is_irreducible(uint8_t poly) {
        if (!(poly & 1)) return false;

        for (uint8_t i = 3; i < 0x20; i += 2) {
            if (!divide((1u << 8) | poly, i).second) return false;
        }
        return true;
    }

    constexpr std::vector<uint8_t> find_irreducible_polynomials() {
        std::vector<uint8_t> result;
        result.reserve(30);
        for (uint8_t i = 1; i < 0xFF; i += 2) {
            if (is_irreducible(i)) result.push_back(i);
        }
        return result;
    }

    inline uint8_t multiply(uint8_t a, uint8_t b, uint8_t mod_poly) {
        static auto irreducible = find_irreducible_polynomials();
        if (std::find(irreducible.begin(), irreducible.end(), mod_poly) == irreducible.end())
            throw std::invalid_argument("Mod is reducible");

        uint8_t result = 0;
        while (b > 0) {
            if (b & 1) result ^= a;
            uint8_t carry = a & 0x80;
            a <<= 1;
            if (carry) a ^= mod_poly;
            b >>= 1;
        }
        return result;
    }
}

#endif //GF_MATH_H
