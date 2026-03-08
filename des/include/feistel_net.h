#ifndef FEISTEL_NETWORK_H
#define FEISTEL_NETWORK_H

#include <memory>
#include <vector>
#include <cstdint>
#include <span>
#include "interface.h"

namespace crypto {
    class FeistelNetwork : public ISymmetricAlgorithm {
    protected:
        std::unique_ptr<IKeyExpansion> _key_expansion;
        std::unique_ptr<IEncryptionTransform> _round_function;
        std::vector<std::vector<uint8_t> > _round_keys;
        size_t _rounds;

    public:
        FeistelNetwork(
            std::unique_ptr<IKeyExpansion> key_expansion,
            std::unique_ptr<IEncryptionTransform> round_function,
            size_t rounds = 16
        );

        FeistelNetwork(const FeistelNetwork &) = delete;

        FeistelNetwork &operator=(const FeistelNetwork &) = delete;

        FeistelNetwork(FeistelNetwork &&) = default;

        FeistelNetwork &operator=(FeistelNetwork &&) = default;

        void set_round_keys(std::span<const uint8_t> encryption_key) override;

        void set_rounds_count(size_t count);

        std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const override;

        std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const override;

        // Геттеры для тестирования
        const std::vector<std::vector<uint8_t> > &get_round_keys() const { return _round_keys; }
        size_t get_rounds_count() const { return _round_keys.size(); }
    };
}

#endif //FEISTEL_NETWORK_H