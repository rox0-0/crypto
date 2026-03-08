// tests/test.cpp
#include <gtest/gtest.h>
#include <iostream>
#include <cstdlib>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <random>
#include <filesystem>
#include <fstream>
#include <chrono>

#include "des_deal.h"
#include "paddings.h"

using namespace crypto;

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string timestamp = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        test_dir = std::filesystem::current_path() / "test_results" / ("test_" + timestamp);
        std::filesystem::create_directories(test_dir);

        std::cout << "Тестовая директория: " << test_dir << std::endl;

        plaintext_8 = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
        key_8 = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
        iv_8 = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

        key_16 = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
                  0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01};
        key_24 = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
                  0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
                  0x33, 0x55, 0x77, 0x99, 0xBB, 0xDD, 0xFF, 0x11};
        iv_16 = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

        find_test_image();
        // Инициализация генератора случайных чисел
        rng.seed(std::random_device{}());
    }

    void TearDown() override {
    }

    std::vector<uint8_t> generate_random_data(size_t length) {
        std::vector<uint8_t> data(length);
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        std::generate(data.begin(), data.end(), [&]() {
            return static_cast<uint8_t>(dist(rng));
        });
        return data;
    }

    void find_test_image() {
        // Места, где будем искать ваше изображение goal.jpg
        std::vector<std::filesystem::path> search_paths = {
            // 1. В текущей директории сборки (build/)
            std::filesystem::current_path() / "goal.jpg",

            // 2. В директории tests/ относительно текущей
            std::filesystem::current_path() / "tests" / "goal.jpg",

            // 3. В родительской директории (проекта)
            std::filesystem::current_path().parent_path() / "goal.jpg",

            // 4. В tests/ родительской директории
            std::filesystem::current_path().parent_path() / "tests" / "goal.jpg",

            // 5. В директории des/tests/ если мы в поддиректории
            std::filesystem::current_path() / "des" / "tests" / "goal.jpg",

            // 6. В домашней директории (на всякий случай)
            std::filesystem::path(std::getenv("HOME")) / "goal.jpg",

            // 7. На рабочем столе
            std::filesystem::path(std::getenv("HOME")) / "Desktop" / "goal.jpg",

            // 8. В загрузках
            std::filesystem::path(std::getenv("HOME")) / "Downloads" / "goal.jpg"
        };

        std::cout << "\nSearching for goal.jpg in following locations:" << std::endl;
        for (const auto& path : search_paths) {
            if (std::filesystem::exists(path)) {
                test_image_path = path;

                return;
            } else {
                std::cout << "не нашлось";
            }
        }

    }

    bool compare_files(const std::filesystem::path& file1, const std::filesystem::path& file2) {
        std::ifstream f1(file1, std::ios::binary | std::ios::ate);
        std::ifstream f2(file2, std::ios::binary | std::ios::ate);

        if (!f1.is_open() || !f2.is_open()) {
            return false;
        }

        if (f1.tellg() != f2.tellg()) {
            return false;
        }

        f1.seekg(0);
        f2.seekg(0);

        const size_t buffer_size = 4096;
        std::vector<char> buffer1(buffer_size);
        std::vector<char> buffer2(buffer_size);

        while (f1 && f2) {
            f1.read(buffer1.data(), buffer_size);
            f2.read(buffer2.data(), buffer_size);

            size_t bytes_read = f1.gcount();
            if (bytes_read != f2.gcount()) {
                return false;
            }

            if (memcmp(buffer1.data(), buffer2.data(), bytes_read) != 0) {
                return false;
            }

            if (bytes_read < buffer_size) {
                break;
            }
        }

        return true;
    }

public:
    std::filesystem::path test_dir;
    std::filesystem::path test_image_path;

    std::vector<uint8_t> plaintext_8;
    std::vector<uint8_t> key_8;
    std::vector<uint8_t> key_16;
    std::vector<uint8_t> key_24;
    std::vector<uint8_t> iv_8;
    std::vector<uint8_t> iv_16;

    std::mt19937 rng;
};

// ====================== БАЗОВЫЕ ТЕСТЫ DES ======================

TEST_F(CryptoTest, DES_BasicEncryptDecrypt) {
    auto des_cipher = std::make_shared<des::BlockCipher>();
    des_cipher->set_round_keys(key_8);

    crypto::CryptoContext ctx(
        des_cipher,
        mode::CipherMode::ECB,
        mode::PaddingMode::PKCS7
    );

    auto encrypted = ctx.encrypt_async(plaintext_8).get();
    auto decrypted = ctx.decrypt_async(encrypted).get();

    EXPECT_EQ(decrypted, plaintext_8);
}

TEST_F(CryptoTest, DES_CBC_PKCS7) {
    auto des_cipher = std::make_shared<des::BlockCipher>();
    des_cipher->set_round_keys(key_8);

    crypto::CryptoContext ctx(
        des_cipher,
        mode::CipherMode::CBC,
        mode::PaddingMode::PKCS7,
        iv_8
    );


    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto encrypted = ctx.encrypt_async(data).get();
    ctx.set_initialization_vector(iv_8);
    auto decrypted = ctx.decrypt_async(encrypted).get();

    EXPECT_EQ(decrypted, data);
}

TEST_F(CryptoTest, DES_AllPaddingSchemes) {
    auto des_cipher = std::make_shared<des::BlockCipher>();
    des_cipher->set_round_keys(key_8);

    std::vector<mode::PaddingMode> padding_modes = {
        mode::PaddingMode::PKCS7,
        mode::PaddingMode::ANSI_X923,
        mode::PaddingMode::ISO_10126
    };

    std::vector<uint8_t> data = generate_random_data(15);

    for (auto padding : padding_modes) {
        crypto::CryptoContext ctx(
            des_cipher,
            mode::CipherMode::CBC,
            padding,
            iv_8
        );

        auto encrypted = ctx.encrypt_async(data).get();
        ctx.set_initialization_vector(iv_8);
        auto decrypted = ctx.decrypt_async(encrypted).get();

        EXPECT_EQ(decrypted, data) << "Failed for padding mode: " << static_cast<int>(padding);
    }
}


TEST_F(CryptoTest, TripleDES_Basic) {
    auto tdes_cipher = std::make_shared<triple_des::ThreeDESCipher>();

    // Тестируем с разными размерами ключей
    std::vector<std::pair<std::vector<uint8_t>, std::string>> key_configs = {
        {{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}, "Single key"},
        {{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
          0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01}, "Two keys"},
        {{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
          0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
          0x33, 0x55, 0x77, 0x99, 0xBB, 0xDD, 0xFF, 0x11}, "Three keys"}
    };

    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    for (const auto& [key, name] : key_configs) {
        tdes_cipher->set_round_keys(key);

        crypto::CryptoContext ctx(
            tdes_cipher,
            mode::CipherMode::CBC,
            mode::PaddingMode::PKCS7,
            iv_8
        );

        auto encrypted = ctx.encrypt_async(data).get();
        ctx.set_initialization_vector(iv_8);
        auto decrypted = ctx.decrypt_async(encrypted).get();

        EXPECT_EQ(decrypted, data) << "Failed for: " << name;
    }
}


TEST_F(CryptoTest, DEAL_Basic) {
    try {
        auto deal_cipher = std::make_shared<deal::DEALImplementation>();
        deal_cipher->set_round_keys(key_16);

        crypto::CryptoContext ctx(
            deal_cipher,
            mode::CipherMode::ECB,
            mode::PaddingMode::PKCS7
        );

        std::vector<uint8_t> data(16, 0xAA);
        auto encrypted = ctx.encrypt_async(data).get();
        auto decrypted = ctx.decrypt_async(encrypted).get();

        EXPECT_EQ(decrypted, data);

        crypto::CryptoContext ctx_cbc(
            deal_cipher,
            mode::CipherMode::CBC,
            mode::PaddingMode::PKCS7,
            iv_16  // 16 байт для DEAL
        );

        std::vector<uint8_t> data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

        auto encrypted2 = ctx_cbc.encrypt_async(data2).get();
        ctx_cbc.set_initialization_vector(iv_16);
        auto decrypted2 = ctx_cbc.decrypt_async(encrypted2).get();

        EXPECT_EQ(decrypted2, data2);

    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

TEST_F(CryptoTest, DES_AllModes) {
    auto des_cipher = std::make_shared<des::BlockCipher>();
    des_cipher->set_round_keys(key_8);

    std::vector<mode::CipherMode> modes = {
        mode::CipherMode::ECB,
        mode::CipherMode::CBC,
        mode::CipherMode::CFB,
        mode::CipherMode::OFB,
        mode::CipherMode::CTR
    };

    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    for (auto mode : modes) {
        crypto::CryptoContext ctx(
            des_cipher,
            mode,
            mode::PaddingMode::PKCS7,
            (mode == mode::CipherMode::ECB) ? std::vector<uint8_t>{} : iv_8
        );

        auto encrypted = ctx.encrypt_async(data).get();

        if (mode != mode::CipherMode::ECB) {
            ctx.set_initialization_vector(iv_8);
        }

        auto decrypted = ctx.decrypt_async(encrypted).get();

        EXPECT_EQ(decrypted, data)
            << "Failed for cipher mode: " << static_cast<int>(mode);
    }
}



TEST_F(CryptoTest, FileEncryptionDecryption) {
    auto des_cipher = std::make_shared<des::BlockCipher>();
    des_cipher->set_round_keys(key_8);

    crypto::CryptoContext ctx(
        des_cipher,
        mode::CipherMode::CBC,
        mode::PaddingMode::PKCS7,
        iv_8
    );

    auto test_data = generate_random_data(123);
    auto input_file = test_dir / "test.bin";

    {
        std::ofstream file(input_file, std::ios::binary);
        file.write(reinterpret_cast<const char*>(test_data.data()), test_data.size());
        std::cout << "Created test file: " << input_file
                  << " (" << test_data.size() << " bytes)" << std::endl;
    }

    auto encrypted_file = test_dir / "test.enc";
    std::cout << "Encrypting to: " << encrypted_file << std::endl;
    ctx.encrypt_async(input_file, encrypted_file).get();

    ctx.set_initialization_vector(iv_8);
    auto decrypted_file = test_dir / "test.dec";
    std::cout << "Decrypting to: " << decrypted_file << std::endl;
    ctx.decrypt_async(encrypted_file, decrypted_file).get();

    EXPECT_TRUE(compare_files(input_file, decrypted_file))
        << "Decrypted file doesn't match original";

    std::cout << "File test completed successfully" << std::endl;
}


TEST_F(CryptoTest, ImageEncryptionDecryption) {
    auto des_cipher = std::make_shared<des::BlockCipher>();
    des_cipher->set_round_keys(key_8);

    if (!std::filesystem::exists(test_image_path)) {
        GTEST_SKIP() << "\n⚠ No image";
    }

    std::cout << "\n=== Testing Image Encryption ===" << std::endl;
    std::cout << "Image: " << test_image_path << std::endl;
    std::cout << "Size: " << std::filesystem::file_size(test_image_path) << " bytes" << std::endl;

    std::vector<std::pair<mode::CipherMode, std::string>> modes = {
        {mode::CipherMode::ECB, "ECB"},
        {mode::CipherMode::CBC, "CBC"},
        {mode::CipherMode::CFB, "CFB"}
    };

    for (const auto& [mode, mode_name] : modes) {
        std::cout << "\n--- Mode: " << mode_name << " ---" << std::endl;

        crypto::CryptoContext ctx(
            des_cipher,
            mode,
            mode::PaddingMode::PKCS7,
            (mode == mode::CipherMode::ECB) ? std::vector<uint8_t>{} : iv_8
        );


        auto encrypted_file = test_dir / ("image_encrypted_" + mode_name + ".bin");
        std::cout << "Encrypting to: " << encrypted_file.filename() << std::endl;

        auto encrypt_start = std::chrono::high_resolution_clock::now();
        ctx.encrypt_async(test_image_path, encrypted_file).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();

        auto encrypted_size = std::filesystem::file_size(encrypted_file);
        std::cout << "Encrypted size: " << encrypted_size << " bytes" << std::endl;

        // Дешифруем изображение
        auto decrypted_file = test_dir / ("image_decrypted_" + mode_name + ".jpg");
        std::cout << "Decrypting to: " << decrypted_file.filename() << std::endl;

        if (mode != mode::CipherMode::ECB) {
            ctx.set_initialization_vector(iv_8);
        }

        auto decrypt_start = std::chrono::high_resolution_clock::now();
        ctx.decrypt_async(encrypted_file, decrypted_file).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();

        auto decrypted_size = std::filesystem::file_size(decrypted_file);
        std::cout << "Decrypted size: " << decrypted_size << " bytes" << std::endl;


        EXPECT_TRUE(compare_files(test_image_path, decrypted_file))
            << "Decrypted image doesn't match original for mode " << mode_name;

        if (!compare_files(test_image_path, decrypted_file)) {
            std::cout << "файлы не совпдают" << std::endl;
        } else {
            std::cout << "файлы совпадают!" << std::endl;
        }

        // Время выполнения
        auto encrypt_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            encrypt_end - encrypt_start);
        auto decrypt_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            decrypt_end - decrypt_start);

        std::cout << "Encryption time: " << encrypt_time.count() << " ms" << std::endl;
        std::cout << "Decryption time: " << decrypt_time.count() << " ms" << std::endl;
        std::cout << "Total time: " << (encrypt_time + decrypt_time).count() << " ms" << std::endl;
    }
}





//граничные случаи

TEST_F(CryptoTest, EmptyDataThrowsException) {
    auto des_cipher = std::make_shared<des::BlockCipher>();
    des_cipher->set_round_keys(key_8);

    crypto::CryptoContext ctx(
        des_cipher,
        mode::CipherMode::CBC,
        mode::PaddingMode::PKCS7,
        iv_8
    );

    std::vector<uint8_t> empty_data;


    EXPECT_THROW({
        auto encrypted = ctx.encrypt_async(empty_data).get();
    }, std::invalid_argument) << "Should throw std::invalid_argument for empty input data";


    EXPECT_THROW({
        auto decrypted = ctx.decrypt_async(empty_data).get();
    }, std::invalid_argument) << "Should throw std::invalid_argument for empty input data";
}

TEST_F(CryptoTest, SingleByteData) {
    auto des_cipher = std::make_shared<des::BlockCipher>();
    des_cipher->set_round_keys(key_8);

    crypto::CryptoContext ctx(
        des_cipher,
        mode::CipherMode::CBC,
        mode::PaddingMode::PKCS7,
        iv_8
    );

    // Тест с одним байтом
    std::vector<uint8_t> single_byte = {0x42};

    auto encrypted = ctx.encrypt_async(single_byte).get();
    ctx.set_initialization_vector(iv_8);
    auto decrypted = ctx.decrypt_async(encrypted).get();

    EXPECT_EQ(decrypted, single_byte);
}



int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);



    int result = RUN_ALL_TESTS();

    if (result == 0) {
        std::cout << "ГОООООООООООООООООООООООООООЛ!" << std::endl;
    } else {
        std::cout << "НТ НТ, ЧЕТО НЕ ТО!" << std::endl;
    }


    return result;
}