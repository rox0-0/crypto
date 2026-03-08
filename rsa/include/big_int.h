#ifndef CRYPTO_BIG_INT_H
#define CRYPTO_BIG_INT_H

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/gmp.hpp>
#include <stdexcept>
#include <tuple>

namespace crypto {
    namespace types {

        namespace mp = boost::multiprecision;
        using BigInt = mp::mpz_int;
        using BigRational = mp::mpq_rational;

    } // namespace types
} // namespace crypto

#endif // CRYPTO_BIG_INT_H