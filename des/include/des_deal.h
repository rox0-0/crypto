#ifndef DES_DEAL_H
#define DES_DEAL_H

#include <vector>
#include <span>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <array>
#include <stdexcept>
#include "feistel_net.h"
#include "interface.h"

namespace crypto {

// DES компоненты
namespace des {
    class KeyScheduler final : public IKeyExpansion {
    public:
        std::vector<std::vector<uint8_t>> generate_round_keys(std::span<const uint8_t> master_key) override;
    };

    class RoundFunction final : public IEncryptionTransform {
    public:
        std::vector<uint8_t> transform(std::span<const uint8_t> data_block,
                                       std::span<const uint8_t> subkey) const override;
    };

    class BlockCipher final : public FeistelNetwork {
    public:
        BlockCipher() : FeistelNetwork(
            std::make_unique<KeyScheduler>(),
            std::make_unique<RoundFunction>(),
            16  // раундов DES
        ) {}

        std::vector<uint8_t> encrypt_block(std::span<const uint8_t> plaintext) const;
        std::vector<uint8_t> decrypt_block(std::span<const uint8_t> ciphertext) const;

        // Реализация ISymmetricAlgorithm
        std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const override {
            return encrypt_block(block);
        }

        std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const override {
            return decrypt_block(block);
        }

        void set_round_keys(std::span<const uint8_t> encryption_key) override {
            FeistelNetwork::set_round_keys(encryption_key);
        }

        [[nodiscard]] size_t get_block_size() const override {
            return 8;
        }
    };
}

// Triple DES компоненты
namespace triple_des {
    class ThreeDESCipher final : public ISymmetricAlgorithm {
        std::array<des::BlockCipher, 3> cipher_instances;

    public:
        ThreeDESCipher() = default;

        // Шифрование: E(K1) → D(K2) → E(K3)
        std::vector<uint8_t> encrypt(std::span<const uint8_t> data_block) const override;

        // Дешифрование: D(K3) → E(K2) → D(K1)
        std::vector<uint8_t> decrypt(std::span<const uint8_t> data_block) const override;

        // Настройка ключей для разных режимов Triple DES
        void set_round_keys(std::span<const uint8_t> encryption_key) override;

        [[nodiscard]] size_t get_block_size() const override;

    private:
        void validate_key_size(size_t key_size) const;
        void setup_two_key_mode(std::span<const uint8_t> key);
        void setup_three_key_mode(std::span<const uint8_t> key);
    };
}

// DEAL компоненты (использует DES как примитив)
namespace deal {
    class DESWrapper final : public IEncryptionTransform {
        friend class DEALImplementation;

        mutable std::unordered_map<uint64_t, std::unique_ptr<des::BlockCipher>> cached_ciphers;

    public:
        std::vector<uint8_t> transform(std::span<const uint8_t> data_block,
                                       std::span<const uint8_t> round_key) const override;
    };

    class DEALKeyDerivation final : public IKeyExpansion {
    public:
        std::vector<std::vector<uint8_t>> generate_round_keys(std::span<const uint8_t> master_key) override;
    };

    class DEALImplementation final : public FeistelNetwork {
    public:
        DEALImplementation() : FeistelNetwork(
            std::make_unique<DEALKeyDerivation>(),
            std::make_unique<DESWrapper>()
        ) {}

        void set_round_keys(std::span<const uint8_t> encryption_key) override;

        std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const override {
            return FeistelNetwork::encrypt(block);
        }

        std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const override {
            return FeistelNetwork::decrypt(block);
        }

        [[nodiscard]] size_t get_block_size() const override {
            return 16;
        }
    };
}

} // namespace crypto

#endif // DES_DEAL_H