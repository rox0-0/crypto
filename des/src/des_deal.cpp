#include "des_deal.h"
#include <stdexcept>
#include <algorithm>

using namespace crypto;

// Встроенная реализация bit operations
namespace crypto::bits {
    enum class BitIndexing {
        LSB_FIRST,
        MSB_FIRST
    };

    enum class StartBit {
        ZERO,
        ONE
    };

    std::vector<uint8_t> permute_bits(std::span<const uint8_t> data, std::span<const uint16_t> p_block,
                                      BitIndexing bit_indexing, StartBit start_bit) {
        const size_t result_bytes = (p_block.size() + 7) / 8;
        std::vector<uint8_t> result(result_bytes, 0);

        for (size_t i = 0; i < p_block.size(); ++i) {
            uint16_t source_bit_pos = p_block[i];

            if (start_bit == StartBit::ONE) {
                source_bit_pos -= 1;
            }
            const uint16_t source_byte_idx = source_bit_pos / 8;
            const uint16_t source_bit_idx = source_bit_pos % 8;
            const uint16_t result_byte_idx = i / 8;
            const uint16_t result_bit_idx = i % 8;

            if (bit_indexing == BitIndexing::LSB_FIRST) {
                bool bit_value = (data[source_byte_idx] >> source_bit_idx) & 1;
                if (bit_value) result[result_byte_idx] |= (1 << result_bit_idx);
            }
            else {
                bool bit_value = (data[source_byte_idx] >> (7 - source_bit_idx)) & 1;
                if (bit_value) {
                    result[result_byte_idx] |= (1 << (7 - result_bit_idx));
                }
            }
        }

        return result;
    }

    void shift_left(uint32_t &num, uint8_t shift) noexcept {
        num = ((num >> (32 - shift)) | (num << shift)) & ((1 << 28) - 1);
    }
}

// ====================== DES Implementation ======================

// Таблицы для DES
namespace {
    // Первоначальная перестановка ключа
    constexpr uint16_t KEY_PERMUTATION_TABLE[] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };

    // Сжатие ключа для раундов
    constexpr uint16_t KEY_COMPRESSION_TABLE[] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    // Таблица расширения для функции F
    constexpr uint16_t EXPANSION_TABLE[] = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };

    // Сдвиги для расписания ключей
    constexpr uint8_t KEY_SHIFTS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    // S-блоки (8x4x16)
    constexpr uint8_t S_BOXES[8][4][16] = {
        {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };

    // Финальная перестановка функции F
    constexpr uint16_t FINAL_PERMUTATION[] = {
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    };

    // Начальная перестановка блока
    constexpr uint16_t INITIAL_PERMUTATION[] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    // Обратная начальная перестановка
    constexpr uint16_t INVERSE_INITIAL_PERMUTATION[] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };
}

std::vector<std::vector<uint8_t>> des::KeyScheduler::generate_round_keys(std::span<const uint8_t> master_key) {
    if (master_key.size() != 8) {
        throw std::invalid_argument("DES ключ должен быть 8 байт");
    }

    std::vector<std::vector<uint8_t>> subkeys;
    subkeys.reserve(16);

    // Первоначальная перестановка ключа
    const auto permuted = bits::permute_bits(master_key, KEY_PERMUTATION_TABLE,
        bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);

    // Извлекаем левую и правую половины
    uint64_t permuted_value = 0;
    for (int i = 0; i < 7; i++) {
        permuted_value = (permuted_value << 8) | permuted[i];
    }

    uint32_t left_half = permuted_value >> 28;
    uint32_t right_half = permuted_value & ((1 << 28) - 1);

    // Генерация 16 раундовых ключей
    for (int round = 0; round < 16; ++round) {
        bits::shift_left(left_half, KEY_SHIFTS[round]);
        bits::shift_left(right_half, KEY_SHIFTS[round]);

        uint64_t combined = (static_cast<uint64_t>(left_half) << 28) | right_half;
        std::vector<uint8_t> combined_bytes(7, 0);

        for (int j = 6; j >= 0; j--) {
            combined_bytes[j] = combined & 0xFF;
            combined >>= 8;
        }

        // Сжатие до 48 бит
        subkeys.push_back(bits::permute_bits(combined_bytes, KEY_COMPRESSION_TABLE,
            bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE));
    }

    return subkeys;
}

std::vector<uint8_t> des::RoundFunction::transform(std::span<const uint8_t> data_block,
                                                   std::span<const uint8_t> subkey) const {
    if (data_block.size() != 4)
        throw std::invalid_argument("Входной блок должен быть 4 байта");
    if (subkey.size() != 6)
        throw std::invalid_argument("Ключ раунда должен быть 6 байт");

    // Расширение до 48 бит
    const auto expanded = bits::permute_bits(data_block, EXPANSION_TABLE,
        bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);

    // XOR с ключом раунда
    std::vector<uint8_t> xored(expanded.size());
    for (size_t i = 0; i < expanded.size(); ++i) {
        xored[i] = expanded[i] ^ subkey[i];
    }

    // Преобразование через S-блоки
    std::vector<uint8_t> sbox_output(4, 0);
    size_t bit_offset = 0;  // ИСПРАВЛЕНО: не const

    for (size_t box = 0; box < 8; ++box) {
        const uint8_t six_bits = xored[box];
        const uint8_t row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
        const uint8_t col = (six_bits >> 1) & 0x0F;
        const uint8_t s_value = S_BOXES[box][row][col];

        // Записываем 4 бита результата
        for (int bit = 0; bit < 4; ++bit) {
            if ((s_value >> (3 - bit)) & 1) {
                sbox_output[bit_offset / 8] |= (1u << (7 - (bit_offset % 8)));
            }
            ++bit_offset;
        }
    }

    // Финальная перестановка
    return bits::permute_bits(sbox_output, FINAL_PERMUTATION,
        bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
}

std::vector<uint8_t> des::BlockCipher::encrypt_block(std::span<const uint8_t> plaintext) const {
    if (plaintext.size() != 8) {
        throw std::invalid_argument("Входной блок должен быть 8 байт");
    }

    auto permuted = bits::permute_bits(plaintext, INITIAL_PERMUTATION,
        bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);

    permuted = FeistelNetwork::encrypt(permuted);

    return bits::permute_bits(permuted, INVERSE_INITIAL_PERMUTATION,
        bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
}

std::vector<uint8_t> des::BlockCipher::decrypt_block(std::span<const uint8_t> ciphertext) const {
    if (ciphertext.size() != 8) {
        throw std::invalid_argument("Входной блок должен быть 8 байт");
    }

    auto permuted = bits::permute_bits(ciphertext, INITIAL_PERMUTATION,
        bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);

    permuted = FeistelNetwork::decrypt(permuted);

    return bits::permute_bits(permuted, INVERSE_INITIAL_PERMUTATION,
        bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
}

// ====================== Triple DES Implementation ======================

void triple_des::ThreeDESCipher::validate_key_size(size_t key_size) const {
    if (key_size != 8 && key_size != 16 && key_size != 24) {
        throw std::invalid_argument(
            "Недопустимый размер ключа Triple DES. "
            "Допустимые размеры: 8, 16 или 24 байта"
        );
    }
}

void triple_des::ThreeDESCipher::setup_two_key_mode(std::span<const uint8_t> key) {
    // Режим с двумя ключами: K1 = K3, K2 - уникальный
    // Ключ 16 байт: первые 8 = K1, вторые 8 = K2
    cipher_instances[0].set_round_keys(key.subspan(0, 8));
    cipher_instances[1].set_round_keys(key.subspan(8, 8));
    cipher_instances[2].set_round_keys(key.subspan(0, 8)); // K3 = K1
}

void triple_des::ThreeDESCipher::setup_three_key_mode(std::span<const uint8_t> key) {
    // Режим с тремя ключами: K1, K2, K3 все разные
    // Ключ 24 байта
    cipher_instances[0].set_round_keys(key.subspan(0, 8));
    cipher_instances[1].set_round_keys(key.subspan(8, 8));
    cipher_instances[2].set_round_keys(key.subspan(16, 8));
}

std::vector<uint8_t> triple_des::ThreeDESCipher::encrypt(std::span<const uint8_t> data_block) const {
    if (data_block.size() != 8) {
        throw std::invalid_argument("Triple DES работает с блоками по 8 байт");
    }

    // Режим E-D-E (Encrypt-Decrypt-Encrypt)
    std::vector<uint8_t> intermediate = cipher_instances[0].encrypt(data_block);
    intermediate = cipher_instances[1].decrypt(intermediate);
    return cipher_instances[2].encrypt(intermediate);
}

std::vector<uint8_t> triple_des::ThreeDESCipher::decrypt(std::span<const uint8_t> data_block) const {
    if (data_block.size() != 8) {
        throw std::invalid_argument("Triple DES работает с блоками по 8 байт");
    }

    // Режим D-E-D (Decrypt-Encrypt-Decrypt) - обратный E-D-E
    std::vector<uint8_t> intermediate = cipher_instances[2].decrypt(data_block);
    intermediate = cipher_instances[1].encrypt(intermediate);
    return cipher_instances[0].decrypt(intermediate);
}

void triple_des::ThreeDESCipher::set_round_keys(std::span<const uint8_t> encryption_key) {
    const size_t key_size = encryption_key.size();
    validate_key_size(key_size);

    if (key_size == 8) {
        // Одиночный ключ DES (режим совместимости)
        cipher_instances[0].set_round_keys(encryption_key);
        cipher_instances[1].set_round_keys(encryption_key);
        cipher_instances[2].set_round_keys(encryption_key);
    }
    else if (key_size == 16) {
        // Двухключевой режим (K1, K2, K1)
        setup_two_key_mode(encryption_key);
    }
    else if (key_size == 24) {
        // Трехключевой режим (K1, K2, K3)
        setup_three_key_mode(encryption_key);
    }
}

size_t triple_des::ThreeDESCipher::get_block_size() const {
    return 8;
}

// ====================== DEAL Implementation ======================

namespace {
    // Константный ключ для DEAL
    constexpr uint8_t DEAL_CONSTANT_KEY[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
}

std::vector<uint8_t> deal::DESWrapper::transform(std::span<const uint8_t> data_block,
                                                 std::span<const uint8_t> round_key) const {
    // Конвертируем ключ в 64-битный идентификатор для кэша
    uint64_t key_id = 0;
    for (uint8_t byte : round_key) {
        key_id = (key_id << 8) | byte;
    }

    // Ищем или создаем DES шифр для этого ключа
    auto cipher_iter = cached_ciphers.find(key_id);
    if (cipher_iter == cached_ciphers.end()) {
        auto cipher = std::make_unique<des::BlockCipher>();
        cipher->set_round_keys(round_key);
        cipher_iter = cached_ciphers.emplace(key_id, std::move(cipher)).first;
    }

    return cipher_iter->second->encrypt(data_block);
}

std::vector<std::vector<uint8_t>> deal::DEALKeyDerivation::generate_round_keys(std::span<const uint8_t> master_key) {
    const size_t key_size = master_key.size();
    if (key_size != 16 && key_size != 24 && key_size != 32) {
        throw std::invalid_argument("Недопустимый размер ключа DEAL");
    }

    const size_t rounds = (key_size == 16) ? 6 : 8;
    std::vector<std::vector<uint8_t>> round_keys;
    round_keys.reserve(rounds);

    // Инициализируем DES с константным ключом
    des::BlockCipher des_cipher;
    des_cipher.set_round_keys(DEAL_CONSTANT_KEY);

    std::vector<uint8_t> current_block(8, 0);

    if (key_size == 16) {
        // DEAL-128
        for (size_t round = 0; round < rounds; ++round) {
            for (size_t i = 0; i < 8; ++i) {
                current_block[i] ^= master_key[(round * 8 + i) % key_size];
            }
            current_block = des_cipher.encrypt(current_block);
            round_keys.push_back(current_block);
        }
    } else if (key_size == 24) {
        // DEAL-192
        for (size_t round = 0; round < rounds; ++round) {
            const size_t key_segment = (round < rounds - 1) ? 16 : 24;
            for (size_t i = 0; i < 8; ++i) {
                current_block[i] ^= master_key[(round * 8 + i) % key_segment];
            }
            current_block = des_cipher.encrypt(current_block);
            round_keys.push_back(current_block);
        }
    } else {
        // DEAL-256
        for (size_t round = 0; round < rounds; ++round) {
            for (size_t i = 0; i < 8; ++i) {
                current_block[i] ^= master_key[(round * 8 + i) % key_size];
            }
            current_block = des_cipher.encrypt(current_block);
            round_keys.push_back(current_block);
        }
    }

    return round_keys;
}

void deal::DEALImplementation::set_round_keys(std::span<const uint8_t> encryption_key) {
    const size_t rounds = (encryption_key.size() == 16) ? 6 : 8;

    // Устанавливаем количество раундов перед генерацией ключей
    set_rounds_count(rounds);  // <-- ДОБАВИТЬ ЭТУ СТРОЧКУ

    // Используем protected метод FeistelNetwork для установки количества раундов
    FeistelNetwork::set_round_keys(encryption_key);

    // Очищаем кэш DES шифров
    auto* wrapper = static_cast<DESWrapper*>(_round_function.get());
    wrapper->cached_ciphers.clear();
}