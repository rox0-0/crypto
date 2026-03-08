//
// Created by lausniko on 13.12.2025.
//

#ifndef MODES_H
#define MODES_H

namespace crypto::mode{
    enum class CipherMode {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RandomDelta
    };

    enum class PaddingMode {
        Zeros,
        ANSI_X923,
        PKCS7,
        ISO_10126
    };
}
#endif //MODES_H
