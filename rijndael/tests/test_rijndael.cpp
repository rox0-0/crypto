//
// Created by lausniko on 14.01.2026.
//
#include <gtest/gtest.h>
#include "GF_math.h"
#include "rijndael.h"
#include <random>
#include <algorithm>
#include <bitset>

namespace crypto::test {

class RijndaelTest : public ::testing::Test {
protected:
    void SetUp() override {
        // AES известные тестовые векторы
        aes128_plaintext = {
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
        };

        aes128_key = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x97, 0x56, 0x19, 0x88, 0x09, 0xcf
        };

        aes128_ciphertext = {
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
        };

        aes192_key = {
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
        };

        aes256_key = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        };
    }

    std::vector<uint8_t> generateRandomData(size_t size) {
        std::vector<uint8_t> data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (auto &byte : data) {
            byte = static_cast<uint8_t>(dis(gen));
        }
        return data;
    }

    bool areVectorsEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        return std::equal(a.begin(), a.end(), b.begin());
    }

    std::vector<uint8_t> aes128_plaintext;
    std::vector<uint8_t> aes128_key;
    std::vector<uint8_t> aes128_ciphertext;
    std::vector<uint8_t> aes192_key;
    std::vector<uint8_t> aes256_key;
};



// Тест AES-192
TEST_F(RijndaelTest, AES192_EncryptDecrypt) {
    rijndael::RijndaelCipher cipher(16, 24, 0x1B);
    cipher.set_round_keys(aes192_key);

    auto test_data = generateRandomData(16);
    auto encrypted = cipher.encrypt(test_data);
    auto decrypted = cipher.decrypt(encrypted);

    EXPECT_TRUE(areVectorsEqual(decrypted, test_data))
        << "AES-192 failed";
}

// Тест AES-256
TEST_F(RijndaelTest, AES256_EncryptDecrypt) {
    rijndael::RijndaelCipher cipher(16, 32, 0x1B);
    cipher.set_round_keys(aes256_key);

    auto test_data = generateRandomData(16);
    auto encrypted = cipher.encrypt(test_data);
    auto decrypted = cipher.decrypt(encrypted);

    EXPECT_TRUE(areVectorsEqual(decrypted, test_data))
        << "AES-256 failed";
}

// Тест Rijndael с блоком 24 байта
TEST_F(RijndaelTest, Rijndael192_EncryptDecrypt) {
    rijndael::RijndaelCipher cipher(24, 24, 0x1B);
    auto key = generateRandomData(24);
    cipher.set_round_keys(key);

    auto test_data = generateRandomData(24);
    auto encrypted = cipher.encrypt(test_data);
    auto decrypted = cipher.decrypt(encrypted);

    EXPECT_TRUE(areVectorsEqual(decrypted, test_data))
        << "Rijndael-192 failed";
}

// Тест Rijndael с блоком 32 байта
TEST_F(RijndaelTest, Rijndael256_EncryptDecrypt) {
    rijndael::RijndaelCipher cipher(32, 32, 0x1B);
    auto key = generateRandomData(32);
    cipher.set_round_keys(key);

    auto test_data = generateRandomData(32);
    auto encrypted = cipher.encrypt(test_data);
    auto decrypted = cipher.decrypt(encrypted);

    EXPECT_TRUE(areVectorsEqual(decrypted, test_data))
        << "Rijndael-256 failed";
}

// Тест разных неприводимых полиномов
TEST_F(RijndaelTest, DifferentPolynomials) {
    auto polys = gf::find_irreducible_polynomials();

    for (auto mod : polys) {
        rijndael::RijndaelCipher cipher(16, 16, mod);
        cipher.set_round_keys(aes128_key);

        auto test_data = generateRandomData(16);
        auto encrypted = cipher.encrypt(test_data);
        auto decrypted = cipher.decrypt(encrypted);

        EXPECT_TRUE(areVectorsEqual(decrypted, test_data))
            << "Failed with polynomial: 0x" << std::hex << static_cast<int>(mod);
    }
}



// Тест на чувствительность к изменениям ключа
TEST_F(RijndaelTest, KeySensitivity) {
    auto original_key = generateRandomData(16);
    auto modified_key = original_key;
    modified_key[0] ^= 0x01; // Изменяем один бит ключа

    rijndael::RijndaelCipher cipher1(16, 16, 0x1B);
    rijndael::RijndaelCipher cipher2(16, 16, 0x1B);

    cipher1.set_round_keys(original_key);
    cipher2.set_round_keys(modified_key);

    auto test_data = generateRandomData(16);
    auto encrypted1 = cipher1.encrypt(test_data);
    auto encrypted2 = cipher2.encrypt(test_data);

    // Шифротексты должны быть разными при разных ключах
    EXPECT_FALSE(areVectorsEqual(encrypted1, encrypted2))
        << "Ciphertext should be different with different keys";
}

// Тест на чувствительность к изменениям открытого текста
TEST_F(RijndaelTest, PlaintextSensitivity) {
    rijndael::RijndaelCipher cipher(16, 16, 0x1B);
    cipher.set_round_keys(aes128_key);

    auto plaintext1 = generateRandomData(16);
    auto plaintext2 = plaintext1;
    plaintext2[0] ^= 0x01; // Изменяем один бит открытого текста

    auto encrypted1 = cipher.encrypt(plaintext1);
    auto encrypted2 = cipher.encrypt(plaintext2);

    // Шифротексты должны быть разными при разных открытых текстах
    EXPECT_FALSE(areVectorsEqual(encrypted1, encrypted2))
        << "Ciphertext should be different with different plaintexts";
}

// Тест разных комбинаций размеров блоков и ключей
TEST_F(RijndaelTest, VariousBlockKeyCombinations) {
    std::vector<std::pair<size_t, size_t>> configurations = {
        {16, 16}, {16, 24}, {16, 32},  // AES совместимые
        {24, 16}, {24, 24}, {24, 32},  // Rijndael-192
        {32, 16}, {32, 24}, {32, 32}   // Rijndael-256
    };

    for (auto [block_size, key_size] : configurations) {
        auto key = generateRandomData(key_size);
        rijndael::RijndaelCipher cipher(block_size, key_size, 0x1B);
        cipher.set_round_keys(key);

        auto test_data = generateRandomData(block_size);
        auto encrypted = cipher.encrypt(test_data);
        auto decrypted = cipher.decrypt(encrypted);

        EXPECT_TRUE(areVectorsEqual(decrypted, test_data))
            << "Failed for block_size: " << block_size
            << ", key_size: " << key_size;
    }
}

// Тест на исключения при неверных размерах
TEST_F(RijndaelTest, InvalidSizesExceptions) {
    // Неверный размер блока
    EXPECT_THROW(rijndael::RijndaelCipher(8, 16, 0x1B), std::invalid_argument);
    EXPECT_THROW(rijndael::RijndaelCipher(20, 16, 0x1B), std::invalid_argument);
    EXPECT_THROW(rijndael::RijndaelCipher(64, 16, 0x1B), std::invalid_argument);

    // Неверный размер ключа
    EXPECT_THROW(rijndael::RijndaelCipher(16, 8, 0x1B), std::invalid_argument);
    EXPECT_THROW(rijndael::RijndaelCipher(16, 20, 0x1B), std::invalid_argument);
    EXPECT_THROW(rijndael::RijndaelCipher(16, 64, 0x1B), std::invalid_argument);
}



// Тест S-box генерации
TEST_F(RijndaelTest, SBoxGeneration) {
    auto s_box = rijndael::RijndaelCipher::generate_s_box(0x1B);
    auto inv_s_box = rijndael::RijndaelCipher::generate_inv_s_box(0x1B);

    // Проверяем, что S-box имеет правильный размер
    EXPECT_EQ(s_box.size(), 256);
    EXPECT_EQ(inv_s_box.size(), 256);

    // Проверяем несколько известных значений AES S-box
    // AES S-box[0x00] = 0x63, S-box[0x53] = 0xED и т.д.
    EXPECT_EQ(s_box[0x00], 0x63);
    EXPECT_EQ(s_box[0x53], 0xED);

    // Проверяем, что S-box и обратный S-box действительно обратные
    for (int i = 0; i < 256; ++i) {
        uint8_t value = static_cast<uint8_t>(i);
        uint8_t transformed = s_box[value];
        uint8_t inverse_transformed = inv_s_box[transformed];
        EXPECT_EQ(inverse_transformed, value)
            << "S-box/inv-s-box mismatch at index: " << i;
    }
}

// Тест на устойчивость к атакам (базовые проверки)
TEST_F(RijndaelTest, BasicSecurityProperties) {
    rijndael::RijndaelCipher cipher(16, 16, 0x1B);
    cipher.set_round_keys(aes128_key);

    // Тест на лавинный эффект
    auto plaintext1 = std::vector<uint8_t>(16, 0x00);
    auto plaintext2 = plaintext1;
    plaintext2[0] = 0x01; // Изменяем только один бит

    auto ciphertext1 = cipher.encrypt(plaintext1);
    auto ciphertext2 = cipher.encrypt(plaintext2);

    // Подсчитываем количество различных битов
    int diff_bits = 0;
    for (size_t i = 0; i < ciphertext1.size(); ++i) {
        uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
        diff_bits += std::bitset<8>(diff).count();
    }

    // При лавинном эффекте должно измениться около 50% битов
    EXPECT_GT(diff_bits, 30); // Больше 30 из 128 битов (≈23%)
    EXPECT_LT(diff_bits, 98); // Меньше 98 из 128 битов (≈77%)
}

} // namespace crypto::test

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}