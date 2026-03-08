//
// Created by lausniko on 13.12.2025.
//
#include "feistel_net.h"
#include <stdexcept>
#include <algorithm>
#include <future>

namespace crypto {
    FeistelNetwork::FeistelNetwork(
        std::unique_ptr<IKeyExpansion> key_expansion,
        std::unique_ptr<IEncryptionTransform> round_function,
        size_t rounds
    ) : _key_expansion(std::move(key_expansion)),
        _round_function(std::move(round_function)),
        _rounds(rounds) {
        if (!_key_expansion) {
            throw std::invalid_argument("Key expansion cannot be null");
        }
        if (!_round_function) {
            throw std::invalid_argument("Round function cannot be null");
        }
        if (_rounds == 0) {
            throw std::invalid_argument("Rounds count must be positive");
        }
    }

    void FeistelNetwork::set_round_keys(std::span<const uint8_t> encryption_key) {
        if (encryption_key.empty()) {
            throw std::invalid_argument("Encryption key cannot be empty");
        }
        _round_keys = _key_expansion->generate_round_keys(encryption_key);

        if (_round_keys.size() < _rounds) {
            throw std::runtime_error("Generated round keys count less than required rounds");
        }
    }

    void FeistelNetwork::set_rounds_count(size_t count) {
        if (count == 0)
            throw std::invalid_argument("Number of rounds must be positive");
        _rounds = count;
    }

    std::vector<uint8_t> FeistelNetwork::encrypt(std::span<const uint8_t> block) const {
        if (_round_keys.size() != _rounds) {
            throw std::runtime_error("Round keys not set");
        }
        if (block.empty()) {
            throw std::invalid_argument("Block cannot be empty");
        }
        if (block.size() % 2 != 0) {
            throw std::invalid_argument("Block size must be even");
        }
        const size_t half_size = block.size() / 2;

        std::vector left(block.begin(), block.begin() + half_size);
        std::vector right(block.begin() + half_size, block.end());

        for (size_t i = 0; i < _rounds; ++i) {
            std::vector<uint8_t> f_result = _round_function->transform(right, _round_keys[i]);
            std::vector<uint8_t> new_left = std::move(right);
            std::vector<uint8_t> new_right(left.size());
            for (size_t j = 0; j < left.size(); ++j) {
                new_right[j] = left[j] ^ f_result[j];
            }
            left = std::move(new_left);
            right = std::move(new_right);
        }
        std::vector<uint8_t> result(block.size());
        std::ranges::copy(right, result.begin());
        std::ranges::copy(left, result.begin() + half_size);

        return result;
    }

    std::vector<uint8_t> FeistelNetwork::decrypt(std::span<const uint8_t> block) const {
        if (_round_keys.size() != _rounds) {
            throw std::runtime_error("Round keys not set");
        }
        if (block.empty()) {
            throw std::invalid_argument("Block cannot be empty");
        }
        if (block.size() % 2 != 0) {
            throw std::invalid_argument("Block size must be even");
        }

        const size_t half_size = block.size() / 2;
        std::vector left(block.begin(), block.begin() + half_size);
        std::vector right(block.begin() + half_size, block.end());

        for (size_t i = 0; i < _rounds; ++i) {
            std::vector<uint8_t> new_left = right;
            std::vector<uint8_t> f_result = _round_function->transform(right, _round_keys[_rounds - 1 - i]);
            std::vector<uint8_t> new_right(left.size());
            for (size_t j = 0; j < left.size(); ++j) {
                new_right[j] = left[j] ^ f_result[j];
            }

            left = std::move(new_left);
            right = std::move(new_right);
        }

        std::vector<uint8_t> result(block.size());
        std::ranges::copy(right, result.begin());
        std::ranges::copy(left, result.begin() + half_size);

        return result;
    }
}