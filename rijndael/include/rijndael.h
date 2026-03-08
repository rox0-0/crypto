#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <vector>
#include <cstdint>
#include <span>
#include <memory>
#include <algorithm>
#include "GF_math.h"

// Убедитесь, что мы в правильном пространстве имен
namespace crypto {
namespace rijndael {

// ==================== Интерфейсы ====================

class IKeyExpansion {
public:
    virtual ~IKeyExpansion() = default;
    virtual std::vector<std::vector<uint8_t>> generate_round_keys(
        std::span<const uint8_t> input_key) = 0;
};

class IEncryptionTransform {
public:
    virtual ~IEncryptionTransform() = default;
    virtual std::vector<uint8_t> transform(
        std::span<const uint8_t> input_block,
        std::span<const uint8_t> round_key) const = 0;
};

class ISymmetricAlgorithm {
public:
    virtual ~ISymmetricAlgorithm() = default;
    virtual void set_round_keys(std::span<const uint8_t> encryption_key) = 0;
    virtual std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const = 0;
    virtual std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const = 0;
    virtual size_t get_block_size() const = 0;
};

// ==================== RijndaelBaseTransform ====================

class RijndaelBaseTransform : public IEncryptionTransform {
protected:
    const uint8_t _mod;
    const size_t _key_size;
    const std::vector<uint8_t> _s_box;

    RijndaelBaseTransform(std::span<const uint8_t> s_box, uint8_t mod, size_t key_size)
        : _mod(mod), _key_size(key_size), _s_box(s_box.begin(), s_box.end()) {}

    static void add_round_key(std::vector<uint8_t>& state, std::span<const uint8_t> key);

    void sub_bytes(std::vector<uint8_t>& state) const;

    [[nodiscard]] size_t validate_sizes(size_t block_size, size_t keys_size) const;
};

// ==================== RijndaelKeyExpansion ====================
    class RijndaelKeyExpansion : public IKeyExpansion {
        const size_t _block_size;
        const std::vector<uint8_t> _s_box;
        size_t _mod;

    public:
        RijndaelKeyExpansion(std::span<const uint8_t> s_box, uint8_t mod, size_t block_size)
            : _block_size(block_size), _s_box(s_box.begin(), s_box.end()), _mod(mod) {}

        std::vector<std::vector<uint8_t>> generate_round_keys(
            std::span<const uint8_t> input_key) override;

        // Сделайте метод публичным
        [[nodiscard]] size_t find_rounds_count(size_t key_size) const;

    private:
        void sub_word(std::vector<uint8_t>& word) const;
        static void rot_word(std::vector<uint8_t>& word) noexcept;
    };

// ==================== RijndaelEncTransform ====================

class RijndaelEncTransform : public RijndaelBaseTransform {
public:
    RijndaelEncTransform(std::span<const uint8_t> s_box, uint8_t mod, size_t key_size)
        : RijndaelBaseTransform(s_box, mod, key_size) {}

    std::vector<uint8_t> transform(std::span<const uint8_t> input_block,
                                   std::span<const uint8_t> round_key) const override;

private:
    static void shift_rows(std::vector<uint8_t>& state);
    void mix_columns(std::vector<uint8_t>& state) const;
};

// ==================== RijndaelDecTransform ====================

class RijndaelDecTransform : public RijndaelBaseTransform {
public:
    RijndaelDecTransform(std::span<const uint8_t> s_box, uint8_t mod, size_t key_size)
        : RijndaelBaseTransform(s_box, mod, key_size) {}

    std::vector<uint8_t> transform(std::span<const uint8_t> input_block,
                                   std::span<const uint8_t> round_key) const override;

private:
    static void inv_shift_rows(std::vector<uint8_t>& state);
    void inv_mix_columns(std::vector<uint8_t>& state) const;
};

// ==================== RijndaelCipher ====================

class RijndaelCipher : public ISymmetricAlgorithm {
    size_t _block_size;
    std::vector<uint8_t> _keys{};
    std::unique_ptr<IEncryptionTransform> _enc_transform;
    std::unique_ptr<IEncryptionTransform> _dec_transform;
    std::unique_ptr<IKeyExpansion> _key_expansion;

public:
    RijndaelCipher(size_t block_size, size_t key_size, uint8_t mod);

    [[nodiscard]] std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const override;
    [[nodiscard]] std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const override;
    void set_round_keys(std::span<const uint8_t> encryption_key) override;
    size_t get_block_size() const override { return _block_size; }

    // Сделайте методы публичными для тестирования
    [[nodiscard]] static std::vector<uint8_t> generate_s_box(uint8_t mod);
    [[nodiscard]] static std::vector<uint8_t> generate_inv_s_box(uint8_t mod);
    static uint8_t shift_left(uint8_t num, uint8_t shift) noexcept;
};

} // namespace rijndael
} // namespace crypto

#endif // RIJNDAEL_H