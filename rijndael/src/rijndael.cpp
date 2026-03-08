#include "../include/rijndael.h"
#include "../include/GF_math.h"
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <bitset>

using namespace crypto::rijndael;

// ==================== RijndaelCipher Implementation ====================

RijndaelCipher::RijndaelCipher(size_t block_size, size_t key_size, uint8_t mod)
    : _block_size(block_size) {

    // Валидация размеров блоков
    if (block_size != 16 && block_size != 24 && block_size != 32) {
        throw std::invalid_argument("Invalid block size. Must be 16, 24, or 32 bytes");
    }

    // Валидация размеров ключей
    if (key_size != 16 && key_size != 24 && key_size != 32) {
        throw std::invalid_argument("Invalid key size. Must be 16, 24, or 32 bytes");
    }

    // Генерация S-box и обратной S-box
    auto s_box = generate_s_box(mod);
    auto inv_s_box = generate_inv_s_box(mod);

    // Создание компонентов шифра
    _enc_transform = std::make_unique<RijndaelEncTransform>(s_box, mod, key_size);
    _dec_transform = std::make_unique<RijndaelDecTransform>(inv_s_box, mod, key_size);
    _key_expansion = std::make_unique<RijndaelKeyExpansion>(s_box, mod, block_size);
}

std::vector<uint8_t> RijndaelCipher::encrypt(std::span<const uint8_t> block) const {
    if (block.size() != _block_size) {
        throw std::invalid_argument("Block size doesn't match cipher block size");
    }
    return _enc_transform->transform(block, _keys);
}

std::vector<uint8_t> RijndaelCipher::decrypt(std::span<const uint8_t> block) const {
    if (block.size() != _block_size) {
        throw std::invalid_argument("Block size doesn't match cipher block size");
    }
    return _dec_transform->transform(block, _keys);
}

void RijndaelCipher::set_round_keys(std::span<const uint8_t> encryption_key) {
    // ЗАКОММЕНТИРУЙТЕ или УДАЛИТЕ эту строку:
    // if (encryption_key.size() != _key_expansion->find_rounds_count(encryption_key.size()) * 4) {
    //     throw std::invalid_argument("Invalid key size for current configuration");
    // }

    // Вместо этого просто проверяйте основные размеры:
    if (encryption_key.size() != 16 && encryption_key.size() != 24 && encryption_key.size() != 32) {
        throw std::invalid_argument("Invalid key size. Must be 16, 24, or 32 bytes");
    }

    _keys.clear();
    auto words = _key_expansion->generate_round_keys(encryption_key);

    for (const auto& word : words) {
        _keys.insert(_keys.end(), word.begin(), word.end());
    }
}

std::vector<uint8_t> RijndaelCipher::generate_s_box(uint8_t mod) {
    std::vector<uint8_t> s_box(256);

    for (int i = 0; i < 256; ++i) {
        uint8_t byte = static_cast<uint8_t>(i);
        uint8_t inv = (byte == 0) ? 0 : gf::inverse(byte, mod);

        // Аффинное преобразование: b' = b ⊕ (b << 1) ⊕ (b << 2) ⊕ (b << 3) ⊕ (b << 4) ⊕ 0x63
        uint8_t transformed = inv ^ shift_left(inv, 1) ^ shift_left(inv, 2) ^
                             shift_left(inv, 3) ^ shift_left(inv, 4) ^ 0x63;

        s_box[i] = transformed;
    }

    return s_box;
}

std::vector<uint8_t> RijndaelCipher::generate_inv_s_box(uint8_t mod) {
    std::vector<uint8_t> inv_s_box(256);

    for (int i = 0; i < 256; ++i) {
        uint8_t byte = static_cast<uint8_t>(i);

        // Обратное аффинное преобразование
        uint8_t transformed = shift_left(byte, 1) ^ shift_left(byte, 3) ^
                             shift_left(byte, 6) ^ 0x05;

        // Обратное преобразование в поле Галуа
        inv_s_box[i] = (transformed == 0) ? 0 : gf::inverse(transformed, mod);
    }

    return inv_s_box;
}

uint8_t RijndaelCipher::shift_left(uint8_t num, uint8_t shift) noexcept {
    return ((num << shift) | (num >> (8 - shift)));
}

// ==================== RijndaelKeyExpansion Implementation ====================

void RijndaelKeyExpansion::sub_word(std::vector<uint8_t>& word) const {
    for (auto& byte : word) {
        byte = _s_box[byte];
    }
}

void RijndaelKeyExpansion::rot_word(std::vector<uint8_t>& word) noexcept {
    if (word.empty()) return;

    uint8_t first = word[0];
    for (size_t i = 0; i < word.size() - 1; ++i) {
        word[i] = word[i + 1];
    }
    word.back() = first;
}

std::vector<std::vector<uint8_t>> RijndaelKeyExpansion::generate_round_keys(
    std::span<const uint8_t> input_key) {

    const size_t key_size = input_key.size();
    const size_t nr = find_rounds_count(key_size);      // Количество раундов
    const size_t nb = _block_size / 4;                  // Количество слов в блоке
    const size_t nk = key_size / 4;                     // Количество слов в ключе
    const size_t words_count = nb * (nr + 1);           // Общее количество слов

    std::vector<std::vector<uint8_t>> round_keys;
    round_keys.reserve(words_count);

    // Инициализация начального ключа
    for (size_t i = 0; i < nk; ++i) {
        round_keys.emplace_back(input_key.begin() + i * 4, input_key.begin() + (i + 1) * 4);
    }

    uint8_t rcon = 1; // Начальное значение Rcon

    // Генерация остальных раундовых ключей
    for (size_t i = nk; i < words_count; ++i) {
        std::vector<uint8_t> temp = round_keys[i - 1];

        if (i % nk == 0) {
            // Применяем rot_word, sub_word и XOR с Rcon
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= rcon;

            // Умножаем rcon на x (0x02) в поле Галуа
            rcon = gf::multiply(rcon, 0x02, static_cast<uint8_t>(_mod));
        }
        else if (nk > 6 && i % nk == 4) {
            // Для ключей размером 256 бит (nk = 8)
            sub_word(temp);
        }

        // XOR с предыдущим словом из того же столбца
        std::vector<uint8_t> new_word(4);
        for (size_t j = 0; j < 4; ++j) {
            new_word[j] = temp[j] ^ round_keys[i - nk][j];
        }

        round_keys.push_back(std::move(new_word));
    }

    return round_keys;
}

size_t RijndaelKeyExpansion::find_rounds_count(size_t key_size) const {
    // Определение количества раундов на основе размеров блока и ключа
    if (_block_size == 16) { // AES
        if (key_size == 16) return 10;
        if (key_size == 24) return 12;
        if (key_size == 32) return 14;
    }
    else if (_block_size == 24) { // Rijndael-192
        if (key_size == 16) return 12;
        if (key_size == 24) return 12;
        if (key_size == 32) return 14;
    }
    else if (_block_size == 32) { // Rijndael-256
        return 14; // Для всех размеров ключей
    }

    throw std::invalid_argument("Invalid key size for current block size");
}

// ==================== RijndaelBaseTransform Implementation ====================

size_t RijndaelBaseTransform::validate_sizes(size_t block_size, size_t keys_size) const {
    size_t num_rounds = 0;

    // Определение количества раундов на основе размера блока и ключа
    if (block_size == 16) {
        if (_key_size == 16) num_rounds = 10;
        else if (_key_size == 24) num_rounds = 12;
        else if (_key_size == 32) num_rounds = 14;
    }
    else if (block_size == 24) {
        if (_key_size == 16 || _key_size == 24) num_rounds = 12;
        else if (_key_size == 32) num_rounds = 14;
    }
    else if (block_size == 32) {
        num_rounds = 14;
    }
    else {
        throw std::invalid_argument("Invalid block size");
    }

    // Проверка размера ключей раундов
    if (keys_size != block_size * (num_rounds + 1)) {
        throw std::invalid_argument("Invalid round key size");
    }

    return num_rounds;
}

void RijndaelBaseTransform::add_round_key(std::vector<uint8_t>& state,
                                          std::span<const uint8_t> key) {
    for (size_t i = 0; i < state.size(); ++i) {
        state[i] ^= key[i];
    }
}

void RijndaelBaseTransform::sub_bytes(std::vector<uint8_t>& state) const {
    for (auto& byte : state) {
        byte = _s_box[byte];
    }
}

// ==================== RijndaelEncTransform Implementation ====================

std::vector<uint8_t> RijndaelEncTransform::transform(
    std::span<const uint8_t> input_block,
    std::span<const uint8_t> round_key) const {

    const size_t block_size = input_block.size();
    const size_t num_rounds = validate_sizes(block_size, round_key.size());

    std::vector<uint8_t> state(input_block.begin(), input_block.end());

    // Начальное преобразование: AddRoundKey
    add_round_key(state, round_key.subspan(0, block_size));

    // Основные раунды
    for (size_t round = 1; round < num_rounds; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key.subspan(round * block_size, block_size));
    }

    // Финальный раунд (без MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key.subspan(num_rounds * block_size, block_size));

    return state;
}

void RijndaelEncTransform::shift_rows(std::vector<uint8_t>& state) {
    const size_t nb = state.size() / 4; // Количество столбцов
    std::vector<uint8_t> temp(state.size());

    // Копируем состояние во временный массив
    std::copy(state.begin(), state.end(), temp.begin());

    // Применяем сдвиги строк
    for (size_t row = 0; row < 4; ++row) {
        for (size_t col = 0; col < nb; ++col) {
            size_t shift = 0;

            // Определяем сдвиг для каждой строки
            if (row == 1) {
                shift = (nb == 8) ? 3 : 1;
            }
            else if (row == 2) {
                shift = (nb == 8) ? 4 : 2;
            }
            else if (row == 3) {
                shift = (nb == 8) ? 5 : 3;
            }

            // Применяем сдвиг
            size_t new_col = (col + shift) % nb;
            state[row + 4 * col] = temp[row + 4 * new_col];
        }
    }
}

void RijndaelEncTransform::mix_columns(std::vector<uint8_t>& state) const {
    const size_t nb = state.size() / 4;

    for (size_t col = 0; col < nb; ++col) {
        size_t base_idx = col * 4;

        // Получаем текущий столбец
        uint8_t s0 = state[base_idx];
        uint8_t s1 = state[base_idx + 1];
        uint8_t s2 = state[base_idx + 2];
        uint8_t s3 = state[base_idx + 3];

        // Применяем матричное умножение в поле Галуа
        state[base_idx]     = gf::multiply(0x02, s0, _mod) ^
                             gf::multiply(0x03, s1, _mod) ^
                             s2 ^ s3;

        state[base_idx + 1] = s0 ^
                             gf::multiply(0x02, s1, _mod) ^
                             gf::multiply(0x03, s2, _mod) ^
                             s3;

        state[base_idx + 2] = s0 ^ s1 ^
                             gf::multiply(0x02, s2, _mod) ^
                             gf::multiply(0x03, s3, _mod);

        state[base_idx + 3] = gf::multiply(0x03, s0, _mod) ^
                             s1 ^ s2 ^
                             gf::multiply(0x02, s3, _mod);
    }
}

// ==================== RijndaelDecTransform Implementation ====================

std::vector<uint8_t> RijndaelDecTransform::transform(
    std::span<const uint8_t> input_block,
    std::span<const uint8_t> round_key) const {

    const size_t block_size = input_block.size();
    const size_t num_rounds = validate_sizes(block_size, round_key.size());

    std::vector<uint8_t> state(input_block.begin(), input_block.end());

    // Начальное преобразование (финальный раунд в обратном порядке)
    add_round_key(state, round_key.subspan(num_rounds * block_size, block_size));

    // Основные раунды в обратном порядке
    for (size_t round = num_rounds - 1; round > 0; --round) {
        inv_shift_rows(state);
        sub_bytes(state);
        add_round_key(state, round_key.subspan(round * block_size, block_size));
        inv_mix_columns(state);
    }

    // Финальный раунд (без InvMixColumns)
    inv_shift_rows(state);
    sub_bytes(state);
    add_round_key(state, round_key.subspan(0, block_size));

    return state;
}

void RijndaelDecTransform::inv_shift_rows(std::vector<uint8_t>& state) {
    const size_t nb = state.size() / 4;
    std::vector<uint8_t> temp(state.size());

    // Копируем состояние во временный массив
    std::copy(state.begin(), state.end(), temp.begin());

    // Применяем обратные сдвиги строк
    for (size_t row = 0; row < 4; ++row) {
        for (size_t col = 0; col < nb; ++col) {
            size_t shift = 0;

            // Определяем сдвиг для каждой строки (обратный шифрованию)
            if (row == 1) {
                shift = (nb == 8) ? 3 : 1;
            }
            else if (row == 2) {
                shift = (nb == 8) ? 4 : 2;
            }
            else if (row == 3) {
                shift = (nb == 8) ? 5 : 3;
            }

            // Применяем обратный сдвиг
            size_t new_col = (col + nb - shift) % nb;
            state[row + 4 * col] = temp[row + 4 * new_col];
        }
    }
}

void RijndaelDecTransform::inv_mix_columns(std::vector<uint8_t>& state) const {
    const size_t nb = state.size() / 4;

    for (size_t col = 0; col < nb; ++col) {
        size_t base_idx = col * 4;

        // Получаем текущий столбец
        uint8_t s0 = state[base_idx];
        uint8_t s1 = state[base_idx + 1];
        uint8_t s2 = state[base_idx + 2];
        uint8_t s3 = state[base_idx + 3];

        // Применяем обратное матричное умножение в поле Галуа
        state[base_idx]     = gf::multiply(0x0E, s0, _mod) ^
                             gf::multiply(0x0B, s1, _mod) ^
                             gf::multiply(0x0D, s2, _mod) ^
                             gf::multiply(0x09, s3, _mod);

        state[base_idx + 1] = gf::multiply(0x09, s0, _mod) ^
                             gf::multiply(0x0E, s1, _mod) ^
                             gf::multiply(0x0B, s2, _mod) ^
                             gf::multiply(0x0D, s3, _mod);

        state[base_idx + 2] = gf::multiply(0x0D, s0, _mod) ^
                             gf::multiply(0x09, s1, _mod) ^
                             gf::multiply(0x0E, s2, _mod) ^
                             gf::multiply(0x0B, s3, _mod);

        state[base_idx + 3] = gf::multiply(0x0B, s0, _mod) ^
                             gf::multiply(0x0D, s1, _mod) ^
                             gf::multiply(0x09, s2, _mod) ^
                             gf::multiply(0x0E, s3, _mod);
    }
}