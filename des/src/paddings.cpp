//
// Created by lausniko on 13.12.2025.
//
#include "paddings.h"
#include <fstream>
#include <functional>
#include <interface.h>
#include <iostream>
#include <random>

#include <thread>
namespace crypto::block {
    std::vector<uint8_t> random_bytes(size_t length);
    std::vector<uint8_t> pad_data(
        std::span<const uint8_t> data,
        mode::PaddingMode mode,
        size_t block_size
    ) {
        if (block_size == 0) {
            throw std::invalid_argument("Invalid block size");
        }

        const size_t pad_len = block_size - (data.size() % block_size);
        const size_t total_length = data.size() + pad_len;

        std::vector result(data.begin(), data.end());
        result.resize(total_length, 0);

        switch (mode) {
            case mode::PaddingMode::Zeros:
                break;

            case mode::PaddingMode::ANSI_X923:
                // Все байты кроме последнего = 0, последний = длина
                for (size_t i = data.size(); i < total_length - 1; ++i) {
                    result[i] = 0;
                }
                result[total_length - 1] = static_cast<uint8_t>(pad_len);
                break;

            case mode::PaddingMode::PKCS7:
                // Все байты набивки = длина
                for (size_t i = data.size(); i < total_length; ++i) {
                    result[i] = static_cast<uint8_t>(pad_len);
                }
                break;

            case mode::PaddingMode::ISO_10126:
                // Случайные байты + последний = длина
                if (pad_len > 1) {
                    auto random = random_bytes(pad_len - 1);
                    std::copy(random.begin(), random.end(),
                              result.begin() + static_cast<ptrdiff_t>(data.size()));
                }
                result[total_length - 1] = static_cast<uint8_t>(pad_len);
                break;
        }

        return result;
    }

    std::vector<uint8_t> unpad_data(
        std::span<const uint8_t> data,
        mode::PaddingMode mode
    ) {
        if (data.empty()) {
            return {};
        }
        switch (mode) {
            case mode::PaddingMode::Zeros: {
                auto it = std::find_if(data.rbegin(), data.rend(),
                                       [](uint8_t byte) { return byte != 0; });

                if (it == data.rend()) {
                    return {};
                }

                const auto end_index = std::distance(data.begin(), it.base());
                return {data.begin(), data.begin() + end_index};
            }
            case mode::PaddingMode::ANSI_X923:
            case mode::PaddingMode::PKCS7:
            case mode::PaddingMode::ISO_10126: {
                const uint8_t pad_len = data[data.size() - 1];
                if (pad_len == 0 || pad_len > data.size()) {
                    throw std::invalid_argument("Invalid padding length");
                }

                if (mode == mode::PaddingMode::PKCS7) {
                    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
                        if (data[i] != pad_len) {
                            throw std::invalid_argument("Invalid PKCS7 padding");
                        }
                    }
                }
                else if (mode == mode::PaddingMode::ANSI_X923) {
                    for (size_t i = data.size() - pad_len; i < data.size() - 1; ++i) {
                        if (data[i] != 0) {
                            throw std::invalid_argument("Invalid ANSI X.923 padding");
                        }
                    }
                }
                return {data.begin(), data.end() - pad_len};
            }
            default: {
                throw std::invalid_argument("Invalid padding mod");
            }
        }
    }

    std::vector<std::vector<uint8_t> > split_blocks(
        std::span<const uint8_t> data,
        size_t block_size
    ) {
        if (block_size == 0) {
            throw std::invalid_argument("Invalid block size");
        }
        if (data.size() % block_size != 0) {
            throw std::invalid_argument("Data length must be multiple of block size");
        }

        std::vector<std::vector<uint8_t> > blocks;
        blocks.reserve(data.size() / block_size);

        for (size_t i = 0; i < data.size(); i += block_size) {
            blocks.emplace_back(data.begin() + i, data.begin() + i + block_size);
        }

        return blocks;
    }

    std::vector<uint8_t> join_blocks(
        std::span<const std::vector<uint8_t>> blocks
    ) {
        size_t total_length = 0;
        for (const auto &block: blocks) {
            total_length += block.size();
        }

        std::vector<uint8_t> result;
        result.reserve(total_length);
        for (const auto &block: blocks) {
            result.insert(result.end(), block.begin(), block.end());
        }
        return result;
    }

    std::vector<uint8_t> random_bytes(size_t length) {
        std::vector<uint8_t> result(length);
        std::random_device rd;
        std::mt19937 mt(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        for (size_t i = 0; i < length; ++i) {
            result[i] = dist(mt);
        }
        return result;
    }
}
namespace crypto {
    CryptoContext::CryptoContext(std::shared_ptr<ISymmetricAlgorithm> algorithm, mode::CipherMode cipher_mode,
                                 mode::PaddingMode padding_mode, std::span<const uint8_t> init_vec,
                                 std::initializer_list<uint8_t> additional_params) : _algorithm(std::move(algorithm)),
        _cipher_mode(cipher_mode), _padding_mode(padding_mode), _init_vec(init_vec.begin(), init_vec.end()),
        _additional_params(additional_params) {
        if (!_algorithm)
            throw std::invalid_argument("Algorithm is nullptr");
        _block_size = _algorithm->get_block_size();
    }

    std::vector<uint8_t> CryptoContext::ProcessECB::operator()(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        const unsigned max_threads = (blocks.size() + _min_blocks_per_thread - 1) / _min_blocks_per_thread;
        const unsigned hardware_threads = std::thread::hardware_concurrency();
        const auto num_threads = std::min(hardware_threads != 0 ? hardware_threads : 2, max_threads);
        const size_t blocks_per_thread = blocks.size() / num_threads;
        std::vector<std::future<std::vector<std::vector<uint8_t> > > > futures(num_threads);
        for (unsigned i = 0; i < num_threads; ++i) {
            const auto policy = i == 0 ? std::launch::deferred : std::launch::async;
            const size_t start_block = i * blocks_per_thread;
            const size_t end_block = i == num_threads - 1 ? blocks.size() : start_block + blocks_per_thread;

            futures[i] = std::async(policy, [this, &blocks, start_block, end_block] {
                std::vector<std::vector<uint8_t> > result;
                result.reserve(end_block - start_block);
                for (auto j = start_block; j < end_block; ++j) {
                    if (_encrypt) result.push_back(_algorithm->encrypt(blocks[j]));
                    else result.push_back(_algorithm->decrypt(blocks[j]));
                }
                return result;
            });
        }
        std::vector<std::vector<uint8_t> > result_blocks;
        result_blocks.reserve(blocks.size());
        std::exception_ptr exception{nullptr};
        auto pos_it = result_blocks.begin();
        for (auto i = 0; i < num_threads; ++i) {
            try {
                auto fut_res = futures[i].get();;
                if (!exception) {
                    result_blocks.insert(result_blocks.end(), fut_res.begin(), fut_res.end());
                }
                pos_it += static_cast<ptrdiff_t>(fut_res.size());
            }
            catch (...) {
                exception = std::current_exception();
            }
        }
        if (exception) {
            std::rethrow_exception(exception);
        }
        return block::join_blocks(result_blocks);
    }

    std::vector<uint8_t> CryptoContext::ProcessPCBC::operator()(const std::vector<uint8_t> &padded_data) const {
        return _encrypt ? encrypt(padded_data) : decrypt(padded_data);
    }

    std::vector<uint8_t> CryptoContext::ProcessPCBC::encrypt(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        std::vector<std::vector<uint8_t> > result;
        result.reserve(blocks.size());
        std::vector<uint8_t> xor_block(_block_size);
        for (auto i = 0; i < blocks.size(); ++i) {
            for (auto j = 0; j < _block_size; ++j) {
                xor_block[j] = blocks[i][j];
                if (i == 0)
                    xor_block[j] ^= _m_prev[j] ^ _c_prev[j];
                else
                    xor_block[j] ^= result[i - 1][j] ^ blocks[i - 1][j];
            }
            result.push_back(_algorithm->encrypt(xor_block));
        }
        _c_prev = result.back();
        _m_prev = std::move(blocks.back());
        return block::join_blocks(result);
    }

    std::vector<uint8_t> CryptoContext::ProcessPCBC::decrypt(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        std::vector<std::vector<uint8_t> > result;
        result.reserve(blocks.size());
        for (auto i = 0; i < blocks.size(); ++i) {
            auto decrypted = _algorithm->decrypt(blocks[i]);
            for (auto j = 0; j < _block_size; ++j) {
                if (i == 0)
                    decrypted[j] ^= _m_prev[j] ^ _c_prev[j];
                else
                    decrypted[j] ^= result[i - 1][j] ^ blocks[i - 1][j];
            }
            result.push_back(std::move(decrypted));
        }
        _m_prev = result.back();
        _c_prev = std::move(blocks.back());
        return block::join_blocks(result);
    }

    std::vector<uint8_t> CryptoContext::ProcessCFB::operator()(const std::vector<uint8_t> &padded_data) const {
        return _encrypt ? encrypt(padded_data) : decrypt(padded_data);
    }

    std::vector<uint8_t> CryptoContext::ProcessCFB::encrypt(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        std::vector<std::vector<uint8_t> > result;
        result.reserve(blocks.size());
        for (auto i = 0; i < blocks.size(); ++i) {
            auto encrypted = _algorithm->encrypt(i == 0 ? _init_vec : result.back());
            for (auto j = 0; j < _block_size; ++j) {
                encrypted[j] ^= blocks[i][j];
            }
            result.push_back(std::move(encrypted));
        }
        _init_vec = result.back();
        return block::join_blocks(result);
    }

    std::vector<uint8_t> CryptoContext::ProcessCFB::decrypt(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        const unsigned max_threads = (blocks.size() + _min_blocks_per_thread - 1) / _min_blocks_per_thread;
        const unsigned hardware_threads = std::thread::hardware_concurrency();
        const auto num_threads = std::min(hardware_threads != 0 ? hardware_threads : 2, max_threads);
        const size_t blocks_per_thread = blocks.size() / num_threads;
        std::vector<std::future<std::vector<std::vector<uint8_t> > > > futures(num_threads);
        for (unsigned i = 0; i < num_threads; ++i) {
            const auto policy = i == 0 ? std::launch::deferred : std::launch::async;
            const size_t start_block = i * blocks_per_thread;
            const size_t end_block = i == num_threads - 1 ? blocks.size() : start_block + blocks_per_thread;

            futures[i] = std::async(policy, [this, &blocks, start_block, end_block] {
                std::vector<std::vector<uint8_t> > result;
                result.reserve(end_block - start_block);
                for (auto j = start_block; j < end_block; ++j) {
                    auto encrypted = _algorithm->encrypt(j == 0 ? _init_vec : blocks[j - 1]);
                    for (auto k = 0; k < _block_size; ++k) {
                        encrypted[k] ^= blocks[j][k];
                    }
                    result.push_back(std::move(encrypted));
                }
                return result;
            });
        }
        std::vector<std::vector<uint8_t> > result_blocks;
        result_blocks.reserve(blocks.size());
        std::exception_ptr exception{nullptr};
        auto pos_it = result_blocks.begin();
        for (auto i = 0; i < num_threads; ++i) {
            try {
                auto fut_res = futures[i].get();;
                if (!exception) {
                    result_blocks.insert(result_blocks.end(), fut_res.begin(), fut_res.end());
                }
                pos_it += static_cast<ptrdiff_t>(fut_res.size());
            }
            catch (...) {
                exception = std::current_exception();
            }
        }
        if (exception) {
            std::rethrow_exception(exception);
        }
        _init_vec = std::move(blocks.back());
        return block::join_blocks(result_blocks);
    }

    std::vector<uint8_t> CryptoContext::ProcessCBC::operator()(const std::vector<uint8_t> &padded_data) const {
        if (_init_vec.size() != _block_size)
            throw std::invalid_argument("incorrect init vector size");
        return _encrypt ? encrypt(padded_data) : decrypt(padded_data);
    }

    std::vector<uint8_t> CryptoContext::ProcessCBC::encrypt(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        std::vector<std::vector<uint8_t> > result;
        result.reserve(blocks.size());
        for (auto i = 0; i < blocks.size(); ++i) {
            for (auto j = 0; j < _block_size; ++j) {
                blocks[i][j] ^= (i == 0 ? _init_vec[j] : result[i - 1][j]);
            }
            auto encrypted = _algorithm->encrypt(blocks[i]);
            result.push_back(std::move(encrypted));
        }
        _init_vec = result.back();
        return block::join_blocks(result);
    }

    std::vector<uint8_t> CryptoContext::ProcessCBC::decrypt(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        const unsigned max_threads = (blocks.size() + _min_blocks_per_thread - 1) / _min_blocks_per_thread;
        const unsigned hardware_threads = std::thread::hardware_concurrency();
        const auto num_threads = std::min(hardware_threads != 0 ? hardware_threads : 2, max_threads);
        const size_t blocks_per_thread = blocks.size() / num_threads;
        std::vector<std::future<std::vector<std::vector<uint8_t> > > > futures(num_threads);
        for (unsigned i = 0; i < num_threads; ++i) {
            const auto policy = i == 0 ? std::launch::deferred : std::launch::async;
            const size_t start_block = i * blocks_per_thread;
            const size_t end_block = i == num_threads - 1 ? blocks.size() : start_block + blocks_per_thread;

            futures[i] = std::async(policy, [this, &blocks, start_block, end_block] {
                std::vector<std::vector<uint8_t> > result;
                result.reserve(end_block - start_block);
                for (auto j = start_block; j < end_block; ++j) {
                    auto decrypted = _algorithm->decrypt(blocks[j]);
                    for (auto k = 0; k < _block_size; ++k) {
                        decrypted[k] ^= (j == 0 ? _init_vec[k] : blocks[j - 1][k]);
                    }
                    result.push_back(std::move(decrypted));
                }
                return result;
            });
        }
        std::vector<std::vector<uint8_t> > result_blocks;
        result_blocks.reserve(blocks.size());
        std::exception_ptr exception{nullptr};
        auto pos_it = result_blocks.begin();
        for (auto i = 0; i < num_threads; ++i) {
            try {
                auto fut_res = futures[i].get();;
                if (!exception) {
                    result_blocks.insert(result_blocks.end(),
                                         fut_res.begin(),
                                         fut_res.end());
                }
                pos_it += static_cast<ptrdiff_t>(fut_res.size());
            }
            catch (...) {
                exception = std::current_exception();
            }
        }
        if (exception) {
            std::rethrow_exception(exception);
        }
        _init_vec = std::move(blocks.back());
        return block::join_blocks(result_blocks);
    }

    std::vector<uint8_t> CryptoContext::ProcessOFB::operator()(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);

        std::vector<std::vector<uint8_t> > o_vec;
        o_vec.reserve(blocks.size());
        o_vec.push_back(_algorithm->encrypt(_init_vec));
        for (auto i = 1; i < blocks.size(); ++i) {
            o_vec.push_back(_algorithm->encrypt(o_vec.back()));
        }
        _init_vec = o_vec.back();
        std::vector<std::vector<uint8_t> > result;
        result.reserve(blocks.size());
        for (auto i = 0; i < blocks.size(); ++i) {
            for (auto j = 0; j < _block_size; ++j) {
                blocks[i][j] ^= o_vec[i][j];
            }
            result.push_back(std::move(blocks[i]));
        }
        return block::join_blocks(result);
    }

    void CryptoContext::ProcessCTR::add_counter(std::vector<uint8_t> &counter, uint64_t val) const {
        if (counter.size() != _block_size)
            throw std::invalid_argument("invalid counter size");
        size_t idx = _block_size - sizeof(uint64_t);
        while (val && idx < counter.size()) {
            uint8_t prev = counter[idx];
            counter[idx] += val & 0xFF;
            val >>= 8;
            if (prev > counter[idx]) val += 1;
        }
    }

    std::vector<uint8_t> CryptoContext::ProcessCTR::operator()(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        const unsigned max_threads = (blocks.size() + _min_blocks_per_thread - 1) / _min_blocks_per_thread;
        const unsigned hardware_threads = std::thread::hardware_concurrency();
        const auto num_threads = std::min(hardware_threads != 0 ? hardware_threads : 2, max_threads);
        const size_t blocks_per_thread = blocks.size() / num_threads;
        std::vector<std::future<std::vector<std::vector<uint8_t> > > > futures(num_threads);
        for (unsigned i = 0; i < num_threads; ++i) {
            const auto policy = i == 0 ? std::launch::deferred : std::launch::async;
            const size_t start_block = i * blocks_per_thread;
            const size_t end_block = i == num_threads - 1 ? blocks.size() : start_block + blocks_per_thread;

            futures[i] = std::async(policy, [this, &blocks, start_block, end_block] {
                std::vector<std::vector<uint8_t> > result;
                result.reserve(end_block - start_block);
                auto counter = _counter;
                add_counter(counter, start_block);
                for (auto j = start_block; j < end_block; ++j) {
                    auto encrypted = _algorithm->encrypt(counter);
                    for (auto k = 0; k < _block_size; ++k) {
                        encrypted[k] ^= blocks[j][k];
                    }
                    result.push_back(std::move(encrypted));
                    add_counter(counter, 1);
                }
                return result;
            });
        }
        std::vector<std::vector<uint8_t> > result_blocks;
        result_blocks.reserve(blocks.size());
        std::exception_ptr exception{nullptr};
        auto pos_it = result_blocks.begin();
        for (auto i = 0; i < num_threads; ++i) {
            try {
                auto fut_res = futures[i].get();;
                if (!exception) {
                    result_blocks.insert(result_blocks.end(), fut_res.begin(), fut_res.end());
                }
                pos_it += static_cast<ptrdiff_t>(fut_res.size());
            }
            catch (...) {
                exception = std::current_exception();
            }
        }
        if (exception) {
            std::rethrow_exception(exception);
        }
        add_counter(_counter, blocks.size());
        return block::join_blocks(result_blocks);
    }

    void CryptoContext::ProcessRandomDelta::add_delta(std::vector<uint8_t> &counter, size_t count) const {
        if (counter.size() != _block_size)
            throw std::invalid_argument("invalid counter size");

        for (auto i = 0; i < count; ++i) {
            uint8_t rem = 0;
            for (auto j = 0; j < _delta.size(); ++j) {
                uint8_t prev = counter[j];
                counter[j] += _delta[j] + rem;
                counter[j] < prev ? rem = 1 : rem = 0;
            }
        }
    }

    std::vector<uint8_t> CryptoContext::ProcessRandomDelta::operator()(const std::vector<uint8_t> &padded_data) const {
        auto blocks = block::split_blocks(padded_data, _block_size);
        std::vector<std::vector<uint8_t> > result_blocks;
        result_blocks.reserve(blocks.size() + 1);
        if (_init_vec.empty()) {
            if (_encrypt) {
                _init_vec = block::random_bytes(_block_size);
                _delta = std::vector(_init_vec.begin() + static_cast<ptrdiff_t>(_block_size / 2),
                                     _init_vec.end());
                result_blocks.push_back(_algorithm->encrypt(_init_vec));
            }
            else {
                _init_vec = _algorithm->decrypt(blocks[0]);
                _delta = std::vector(_init_vec.begin() + static_cast<ptrdiff_t>(_block_size / 2),
                                     _init_vec.end());
                blocks.erase(blocks.begin());
            }
        }
        const unsigned max_threads = (blocks.size() + _min_blocks_per_thread - 1) / _min_blocks_per_thread;
        const unsigned hardware_threads = std::thread::hardware_concurrency();
        const auto num_threads = std::min(hardware_threads != 0 ? hardware_threads : 2, max_threads);
        const size_t blocks_per_thread = blocks.size() / num_threads;

        std::vector<std::future<std::vector<std::vector<uint8_t> > > > futures(num_threads);
        for (unsigned i = 0; i < num_threads; ++i) {
            const auto policy = i == 0 ? std::launch::deferred : std::launch::async;
            const size_t start_block = i * blocks_per_thread;
            const size_t end_block = i == num_threads - 1 ? blocks.size() : start_block + blocks_per_thread;

            futures[i] = std::async(policy, [this, &blocks, start_block, end_block] {
                std::vector<std::vector<uint8_t> > result;
                result.reserve(end_block - start_block);
                auto counter = _init_vec;
                add_delta(counter, start_block);
                if (_encrypt) {
                    for (auto j = start_block; j < end_block; ++j) {
                        for (auto k = 0; k < _block_size; ++k) {
                            blocks[j][k] ^= counter[k];
                        }
                        result.push_back(_algorithm->encrypt(blocks[j]));
                        add_delta(counter, 1);
                    }
                }
                else {
                    for (auto j = start_block; j < end_block; ++j) {
                        auto encrypted = _algorithm->decrypt(blocks[j]);
                        for (auto k = 0; k < _block_size; ++k) {
                            encrypted[k] ^= counter[k];
                        }
                        result.push_back(std::move(encrypted));
                        add_delta(counter, 1);
                    }
                }
                return result;
            });
        }

        std::exception_ptr exception{nullptr};
        auto pos_it = result_blocks.begin();
        for (auto i = 0; i < num_threads; ++i) {
            try {
                auto fut_res = futures[i].get();;
                if (!exception) {
                    result_blocks.insert(result_blocks.end(), fut_res.begin(), fut_res.end());
                }
                pos_it += static_cast<ptrdiff_t>(fut_res.size());
            }
            catch (...) {
                exception = std::current_exception();
            }
        }
        if (exception) {
            std::rethrow_exception(exception);
        }
        add_delta(_init_vec, blocks.size());
        return block::join_blocks(result_blocks);
    }

    std::unique_ptr<CryptoContext::IProcessMode> CryptoContext::create_process_mode(bool encrypt) const {
        switch (_cipher_mode) {
            case mode::CipherMode::ECB:
                return std::make_unique<ProcessECB>(_algorithm, _block_size, encrypt);
            case mode::CipherMode::CBC:
                return std::make_unique<ProcessCBC>(_algorithm, _block_size, _init_vec, encrypt);
            case mode::CipherMode::PCBC:
                return std::make_unique<ProcessPCBC>(_algorithm, _block_size, _init_vec, encrypt);
            case mode::CipherMode::CFB:
                return std::make_unique<ProcessCFB>(_algorithm, _block_size, _init_vec, encrypt);
            case mode::CipherMode::OFB:
                return std::make_unique<ProcessOFB>(_algorithm, _block_size, _init_vec, encrypt);
            case mode::CipherMode::CTR:
                return std::make_unique<ProcessCTR>(_algorithm, _block_size, _init_vec, encrypt);
            case mode::CipherMode::RandomDelta:
                return std::make_unique<ProcessRandomDelta>(_algorithm, _block_size, encrypt);
        }
    }

    std::future<std::vector<uint8_t> > CryptoContext::encrypt_async(std::span<const uint8_t> input_data) {
        if (input_data.empty())
            throw std::invalid_argument("input data is empty");

        auto task = [block_size = _block_size, padding_mode = _padding_mode,
                    process_func = create_process_mode(), data = std::vector(input_data.begin(), input_data.end())] {
            auto padded = block::pad_data(data, padding_mode, block_size);
            auto encrypted = (*process_func)(padded);
            return encrypted;
        };
        return std::async(std::move(task));
    }

    std::future<std::vector<uint8_t> > CryptoContext::decrypt_async(std::span<const uint8_t> input_data) {
        if (input_data.empty())
            throw std::invalid_argument("input data is empty");

        auto task = [block_size = _block_size, padding_mode = _padding_mode,
                    process_func = create_process_mode(false), data = std::vector(input_data.begin(), input_data.end())
                ] {
            auto decrypted = (*process_func)(data);
            return block::unpad_data(decrypted, padding_mode);
        };
        return std::async(std::move(task));
    }

    void CryptoContext::set_algorithm(std::unique_ptr<ISymmetricAlgorithm> algorithm) {
        _algorithm = std::move(algorithm);
    }

    void CryptoContext::set_initialization_vector(std::span<const uint8_t> iv) {
        _init_vec = std::vector(iv.begin(), iv.end());
    }

    std::future<std::filesystem::path> CryptoContext::encrypt_async(const std::filesystem::path &input_file,
                                                                    const std::filesystem::path &output_file) {
        auto task = [block_size = _block_size, padding_mode = _padding_mode, input_file, output_file,
                    process_func = create_process_mode()] {
            auto out_file = output_file;
            if (output_file.empty()) {
                out_file = input_file;
                out_file.replace_extension(".encrypted");
            }
            std::ifstream in(input_file, std::ios::binary);
            std::ofstream out(out_file, std::ios::binary);

            if (!in.is_open())
                throw std::invalid_argument("failed to open input file");
            if (!out.is_open())
                throw std::invalid_argument("failed to open output file");

            std::vector<uint8_t> buffer(block_size * 1024);
            while (in.read(reinterpret_cast<char *>(buffer.data()), static_cast<long>(buffer.size()))) {
                auto encrypted = (*process_func)(buffer);
                out.write(reinterpret_cast<char *>(encrypted.data()), static_cast<long>(encrypted.size()));
            }
            buffer.resize(static_cast<size_t>(in.gcount()));
            auto padded = block::pad_data(buffer, padding_mode, block_size);
            auto encrypted = (*process_func)(padded);
            out.write(reinterpret_cast<char *>(encrypted.data()), static_cast<long>(encrypted.size()));
            return out_file;
        };
        return std::async(std::move(task));
    }

    std::future<std::filesystem::path> CryptoContext::decrypt_async(const std::filesystem::path &input_file,
                                                                    const std::filesystem::path &output_file) {
        auto task = [block_size = _block_size, padding_mode = _padding_mode, input_file, output_file,
                    process_func = create_process_mode(false)] {
            auto out_file = output_file;
            if (output_file.empty()) {
                out_file = input_file;
                out_file.replace_extension(".encrypted");
            }
            std::ifstream in(input_file, std::ios::binary);
            std::ofstream out(out_file, std::ios::binary);
            if (!in.is_open())
                throw std::invalid_argument("failed to open input file: " + input_file.string());
            if (!out.is_open())
                throw std::invalid_argument("failed to open output file: " + out_file.string());

            std::vector<uint8_t> buffer(block_size * 1024);

            in.seekg(0, std::ios::end);
            size_t file_size = in.tellg();
            in.seekg(0);
            size_t cur_size = 0;
            while (in.read(reinterpret_cast<char *>(buffer.data()), static_cast<long>(buffer.size()))) {
                cur_size += in.gcount();
                if (cur_size == file_size) break;
                auto decrypted = (*process_func)(buffer);
                out.write(reinterpret_cast<const char *>(decrypted.data()), static_cast<long>(decrypted.size()));
            }

            size_t last_chunk_size = in.gcount();
            buffer.resize(last_chunk_size);

            auto decrypted = (*process_func)(buffer);;
            auto unpadded = block::unpad_data(decrypted, padding_mode);
            out.write(reinterpret_cast<const char *>(unpadded.data()), static_cast<long>(unpadded.size()));
            return out_file;
        };
        return std::async(std::move(task));
    }
};
