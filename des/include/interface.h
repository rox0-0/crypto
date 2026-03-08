//
// Created by lausniko on 13.12.2025.
//

#ifndef INTERFACE_H
#define INTERFACE_H
class IKeyExpansion {
public:
    virtual ~IKeyExpansion() = default;

    virtual std::vector<std::vector<uint8_t> > generate_round_keys(
        std::span<const uint8_t> input_key
    ) = 0;
};

class IEncryptionTransform {
public:
    virtual ~IEncryptionTransform() = default;

    virtual std::vector<uint8_t> transform(
        std::span<const uint8_t> input_block,
        std::span<const uint8_t> round_key
    ) const = 0;
};

class ISymmetricAlgorithm {
public:
    virtual ~ISymmetricAlgorithm() = default;

    virtual void set_round_keys(std::span<const uint8_t> encryption_key) = 0;

    virtual std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const = 0;

    virtual std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const = 0;

    [[nodiscard]] virtual size_t get_block_size() const = 0;
};

#endif //INTERFACE_H
