//
// Created by lausniko on 13.12.2025.
//

#ifndef PADDINGS_H
#define PADDINGS_H


#include <memory>
#include <vector>
#include <cstdint>
#include <span>
#include <future>
#include <filesystem>
#include <variant>
#include "interface.h"
#include "modes.h"

namespace crypto {
    class CryptoContext {
    private:
        std::shared_ptr<ISymmetricAlgorithm> _algorithm;
        mode::CipherMode _cipher_mode;
        mode::PaddingMode _padding_mode;
        std::vector<uint8_t> _init_vec;
        std::vector<uint8_t> _additional_params;
        size_t _block_size;
        mutable std::vector<uint8_t> _prev_value = {};
        static constexpr unsigned _min_blocks_per_thread = 10;

    public:
        CryptoContext(
            std::shared_ptr<ISymmetricAlgorithm> algorithm,
            mode::CipherMode cipher_mode,
            mode::PaddingMode padding_mode,
            std::span<const uint8_t> init_vec = {},
            std::initializer_list<uint8_t> additional_params = {}
        );

        CryptoContext(const CryptoContext &) = delete;

        CryptoContext &operator=(const CryptoContext &) = delete;

        std::future<std::vector<uint8_t> > encrypt_async(
            std::span<const uint8_t> input_data
        );

        std::future<std::vector<uint8_t> > decrypt_async(
            std::span<const uint8_t> input_data
        );

        std::future<std::filesystem::path> encrypt_async(
            const std::filesystem::path &input_file, const std::filesystem::path &output_file = {}
        );

        std::future<std::filesystem::path> decrypt_async(
            const std::filesystem::path &input_file, const std::filesystem::path &output_file = {}
        );

        // Setters
        void set_algorithm(std::unique_ptr<ISymmetricAlgorithm> algorithm);

        void set_initialization_vector(std::span<const uint8_t> iv);

        // Getters
        [[nodiscard]] mode::CipherMode get_cipher_mode() const { return _cipher_mode; }
        [[nodiscard]] mode::PaddingMode get_padding_mode() const { return _padding_mode; }
        [[nodiscard]] const std::vector<uint8_t> &get_init_vec() const { return _init_vec; }

    private:
        class IProcessMode {
        protected:
            bool _encrypt;
            size_t _block_size;
            std::shared_ptr<ISymmetricAlgorithm> _algorithm;

        public:
            IProcessMode(std::shared_ptr<ISymmetricAlgorithm> algorithm, size_t block_size,
                         bool encrypt = true) : _encrypt(encrypt), _block_size(block_size),
                                                _algorithm(std::move(algorithm)) {}

            IProcessMode(const IProcessMode &) = delete;

            IProcessMode &operator=(const IProcessMode &) = delete;

            IProcessMode &operator=(IProcessMode &&) = default;

            IProcessMode(IProcessMode &&) = default;

            virtual ~IProcessMode() = default;

            virtual std::vector<uint8_t> operator()(const std::vector<uint8_t> &padded_data) const = 0;
        };

        class ProcessECB final : public IProcessMode {
        public:
            ProcessECB(std::shared_ptr<ISymmetricAlgorithm> algorithm, size_t block_size,
                       bool encrypt = true) : IProcessMode(std::move(algorithm), block_size, encrypt) {}

            std::vector<uint8_t> operator()(const std::vector<uint8_t> &padded_data) const override;
        };


        class ProcessCBC final : public IProcessMode {
            mutable std::vector<uint8_t> _init_vec;

        public:
            ProcessCBC(std::shared_ptr<ISymmetricAlgorithm> algorithm, size_t block_size, std::vector<uint8_t> init_vec,
                       bool encrypt = true) : IProcessMode(std::move(algorithm), block_size, encrypt),
                                              _init_vec(std::move(init_vec)) {}

            std::vector<uint8_t> operator()(const std::vector<uint8_t> &padded_data) const override;

        private:
            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &padded_data) const;

            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &padded_data) const;
        };


        class ProcessPCBC final : public IProcessMode {
            mutable std::vector<uint8_t> _m_prev;
            mutable std::vector<uint8_t> _c_prev;

        public:
            ProcessPCBC(std::shared_ptr<ISymmetricAlgorithm> algorithm, size_t block_size,
                        std::vector<uint8_t> init_vec,
                        bool encrypt = true) : IProcessMode(std::move(algorithm), block_size, encrypt),
                                               _m_prev(std::move(init_vec)), _c_prev(_m_prev) {}

            std::vector<uint8_t> operator()(const std::vector<uint8_t> &padded_data) const override;

        private:
            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &padded_data) const;

            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &padded_data) const;
        };


        class ProcessCFB final : public IProcessMode {
            mutable std::vector<uint8_t> _init_vec;

        public:
            ProcessCFB(std::shared_ptr<ISymmetricAlgorithm> algorithm, size_t block_size, std::vector<uint8_t> init_vec,
                       bool encrypt = true) : IProcessMode(std::move(algorithm), block_size, encrypt),
                                              _init_vec(std::move(init_vec)) {}

            std::vector<uint8_t> operator()(const std::vector<uint8_t> &padded_data) const override;

        private:
            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &padded_data) const;

            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &padded_data) const;
        };


        class ProcessOFB final : public IProcessMode {
            mutable std::vector<uint8_t> _init_vec;

        public:
            ProcessOFB(std::shared_ptr<ISymmetricAlgorithm> algorithm, size_t block_size, std::vector<uint8_t> init_vec,
                       bool encrypt = true) : IProcessMode(std::move(algorithm), block_size, encrypt),
                                              _init_vec(std::move(init_vec)) {}

            std::vector<uint8_t> operator()(const std::vector<uint8_t> &padded_data) const override;
        };

        class ProcessCTR final : public IProcessMode {
            mutable std::vector<uint8_t> _counter;

            void add_counter(std::vector<uint8_t> &counter, uint64_t val) const;

        public:
            ProcessCTR(std::shared_ptr<ISymmetricAlgorithm> algorithm, size_t block_size, std::vector<uint8_t> counter,
                       bool encrypt = true) : IProcessMode(std::move(algorithm), block_size, encrypt),
                                              _counter(std::move(counter)) {
                _counter.resize(block_size, 0);
            }

            std::vector<uint8_t> operator()(const std::vector<uint8_t> &padded_data) const override;
        };

        class ProcessRandomDelta final : public IProcessMode {
            mutable std::vector<uint8_t> _delta = {};
            mutable std::vector<uint8_t> _init_vec = {};

            void add_delta(std::vector<uint8_t> &counter, size_t count) const;

        public:
            ProcessRandomDelta(std::shared_ptr<ISymmetricAlgorithm> algorithm, size_t block_size,
                               bool encrypt = true) : IProcessMode(std::move(algorithm), block_size, encrypt) {}

            std::vector<uint8_t> operator()(const std::vector<uint8_t> &padded_data) const override;
        };

        std::unique_ptr<IProcessMode> create_process_mode(bool encrypt = true) const;
    };
}

#endif //PADDINGS_H
