#ifndef _PRIMARY_TESTS_
#define _PRIMARY_TESTS_

#include <stdexcept>
#include <bits/random.h>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>

namespace crypto::primary {
    class IProbabilisticPrimalityTest {
    public:
        // propability [0.5, 1)
        [[nodiscard]] virtual bool is_primary(const BigInt &n, double probability) const = 0;

        virtual ~IProbabilisticPrimalityTest() = default;
    };

    class ProbabilisticPrimalityTest : public IProbabilisticPrimalityTest {
        const int probabilistic_coef; // 2 or 4 for different tests

        [[nodiscard]] virtual bool _is_primary(const BigInt &n, const BigInt &a) const = 0;

    public:
        explicit ProbabilisticPrimalityTest(short probabilistic_coef = 2) : probabilistic_coef(probabilistic_coef) {}

        ~ProbabilisticPrimalityTest() override = default;

        [[nodiscard]]
        bool is_primary(const BigInt &n, const double probability) const override {
            if (probability < 0.5 || probability >= 1.) {
                throw std::invalid_argument("probability not in [0.5; 1)");
            }
            if (n == 2) return true;
            if (!(n & 1)) return false;

            const std::size_t rounds = round_count(probability);
            namespace rnd = boost::random;
            static rnd::mt19937_64 gen(static_cast<unsigned int>(std::time(nullptr)));
            const rnd::uniform_int_distribution<BigInt> dist(BigInt(2), n - 1);

            for (size_t cnt = 0; cnt < rounds; ++cnt) {
                const BigInt a = dist(gen);
                if (a == n) return true;
                if (!_is_primary(n, a)) return false;
            }
            return true;
        }

    protected:
        [[nodiscard]]
        constexpr virtual size_t round_count(const double probability) const {
            if (probability < 0. || probability >= 1.) {
                throw std::invalid_argument("probability not in [0; 1)");
            }

            // x >= log(1/c)(1 - p) = -ln(1-p) / ln(c)
            return static_cast<size_t>(
                std::ceil(-std::log(1.0 - probability) / std::log(static_cast<double>(probabilistic_coef))));
        }
    };

    class FermatTest final : public ProbabilisticPrimalityTest {
        [[nodiscard]] bool _is_primary(const BigInt &n, const BigInt &a) const override {
            if (math::compute_gcd(a, n) == 1) {
                return math::modular_power(a, n - 1, n) == 1;
            }
            return false;
        }
    };

    class SolovayStrassenTest final : public ProbabilisticPrimalityTest {
        [[nodiscard]] bool _is_primary(const BigInt &n, const BigInt &a) const override {
            if (math::compute_gcd(a, n) == 1) {
                int jacobi = math::jacobi_symbol(a, n);
                BigInt pow = math::modular_power(a, (n - 1) / 2, n);
                if (jacobi == -1) return pow == n - 1;
                return pow == jacobi;
            }
            return false;
        }
    };

    class MillerRabinTest final : public ProbabilisticPrimalityTest {
        [[nodiscard]] bool _is_primary(const BigInt &n, const BigInt &a) const override {
            BigInt s = n - 1;
            size_t d = 0;
            while (s % 2 == 0) {
                s /= 2;
                ++d;
            }
            BigInt x = math::modular_power(a, s, n);
            if (x == 1) {
                return true;
            }
            for (size_t i = 0; i < d; ++i) {
                if (x == n - 1) {
                    return true;
                }
                x = math::modular_power(x, 2, n);
            }
            return false;
        }

    public:
        MillerRabinTest() : ProbabilisticPrimalityTest(4) {}
    };
}

#endif // _PRIMARY_TESTS_