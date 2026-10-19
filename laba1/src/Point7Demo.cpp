#include <iostream>
#include <iomanip>
#include <utility>
#include <vector>
#include <fstream>
#include <iterator>
#include <cstdio>
#include <exception>
#include <string>

#include "Point7Demo.h"
#include "DEAL/DEAL.h"
#include <random>
#include <future>
#include "CryptoContext.h"

void printHex7(const type& data)
{
    for (uint8_t byte : data) {
        std::cout << std::uppercase
                  << std::hex
                  << std::setw(2)
                  << std::setfill('0')
                  << static_cast<int>(byte)
                  << ' ';
    }

    std::cout << std::dec << '\n';
}

void testRandomArrays7()
{
    std::cout << "\nRandom arrays test (DEAL + ECB + PKCS7)\n";

    const std::vector<std::pair<std::string, type>> keys = {
        {"128-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF
        }},
        {"192-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10
        }},
        {"256-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77
        }}
    };

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, 255);

    const std::vector<size_t> lengths = {
        0, 1, 7, 8, 15, 16, 17, 32, 64, 100
    };

    for (const auto& [keyName, key] : keys) {
        std::cout << "\nKey size: " << keyName << '\n';

        DEAL deal;
        deal.setKey(key);

        for (size_t length : lengths) {
            type original(length);

            for (uint8_t& byte : original) {
                byte = static_cast<uint8_t>(
                    distribution(generator)
                );
            }

            try {
                CryptoContext context(
                    deal,
                    key,
                    CipherMode::ECB,
                    PaddingMode::PKCS7
                );

                type encrypted = context.encrypt(original).get();
                type decrypted = context.decrypt(encrypted).get();

                std::cout << "Length: " << length
                          << " bytes — "
                          << (decrypted == original ? "OK" : "FAIL")
                          << '\n';
            }
            catch (...) {
                std::cout << "Length: " << length
                          << " bytes — ERROR\n";
            }
        }
    }
}

void testCipherModes7()
{
    std::cout << "\nCipher modes test (DEAL + PKCS7)\n";

    const std::vector<std::pair<std::string, type>> keys = {
        {"128-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF
        }},
        {"192-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10
        }},
        {"256-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77
        }}
    };

    const type iv = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0x10, 0x32, 0x54, 0x76,
        0x98, 0xBA, 0xDC, 0x01
    };

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, 255);

    type original(37);

    for (uint8_t& byte : original) {
        byte = static_cast<uint8_t>(
            distribution(generator)
        );
    }

    const std::vector<std::pair<CipherMode, std::string>> modes = {
        {CipherMode::ECB, "ECB"},
        {CipherMode::CBC, "CBC"},
        {CipherMode::PCBC, "PCBC"},
        {CipherMode::CFB, "CFB"},
        {CipherMode::OFB, "OFB"},
        {CipherMode::CTR, "CTR"},
        {CipherMode::RANDOM_DELTA, "Random Delta"}
    };

    for (const auto& [keyName, key] : keys) {
        std::cout << "\nKey size: " << keyName << '\n';

        DEAL deal;
        deal.setKey(key);

        for (const auto& [mode, name] : modes) {
            try {
                const type currentIV =
                    mode == CipherMode::ECB ? type{} : iv;

                CryptoContext context(
                    deal,
                    key,
                    mode,
                    PaddingMode::PKCS7,
                    currentIV
                );

                type encrypted = context.encrypt(original).get();
                type decrypted = context.decrypt(encrypted).get();

                std::cout << name << ": "
                          << (decrypted == original ? "OK" : "FAIL")
                          << '\n';
            }
            catch (...) {
                std::cout << name << ": ERROR\n";
            }
        }
    }
}

void testPaddingModes7()
{
    std::cout << "\nPadding modes test (DEAL + ECB)\n";

    const std::vector<std::pair<std::string, type>> keys = {
        {"128-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF
        }},
        {"192-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10
        }},
        {"256-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77
        }}
    };

    const type original = {
        1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13
    };

    const std::vector<std::pair<PaddingMode, std::string>> paddings = {
        {PaddingMode::Zeros, "Zeros"},
        {PaddingMode::ANSI_X923, "ANSI_X923"},
        {PaddingMode::PKCS7, "PKCS7"},
        {PaddingMode::ISO10126, "ISO10126"}
    };

    for (const auto& [keyName, key] : keys) {
        std::cout << "\nKey size: " << keyName << '\n';

        DEAL deal;
        deal.setKey(key);

        for (const auto& [padding, name] : paddings) {
            try {
                CryptoContext context(
                    deal,
                    key,
                    CipherMode::ECB,
                    padding
                );

                type encrypted = context.encrypt(original).get();
                type decrypted = context.decrypt(encrypted).get();

                std::cout << name << ": "
                          << (decrypted == original ? "OK" : "FAIL")
                          << '\n';
            }
            catch (...) {
                std::cout << name << ": ERROR\n";
            }
        }
    }
}

void testFileEncryption7(
    const std::string& inputPath,
    CipherMode mode
)
{
    std::cout << "\nFile: " << inputPath << '\n';

    const std::vector<std::pair<std::string, type>> keys = {
        {"128-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF
        }},
        {"192-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10
        }},
        {"256-bit", {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77
        }}
    };

    const type iv = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0x10, 0x32, 0x54, 0x76,
        0x98, 0xBA, 0xDC, 0x01
    };

    const std::string encryptedPath = inputPath + ".enc";
    const std::string decryptedPath = inputPath + ".dec";

    try {
        std::cout << "Path: [" << inputPath << "]\n";
        std::cout << "Path length: " << inputPath.size() << '\n';

        std::ifstream inputFile(inputPath, std::ios::binary);

        if (!inputFile) {
            std::cout << "Cannot open input file: FAIL\n";
            return;
        }

        type original{
            std::istreambuf_iterator<char>(inputFile),
            std::istreambuf_iterator<char>()
        };

        inputFile.close();

        for (const auto& [keyName, key] : keys) {
            std::cout << "\nKey size: " << keyName << '\n';

            DEAL deal;
            deal.setKey(key);

            CryptoContext context(
                deal,
                key,
                mode,
                PaddingMode::PKCS7,
                iv
            );

            std::cout << "Encrypting file...\n";
            context.encrypt(inputPath, encryptedPath).get();
            std::cout << "Encryption finished.\n";

            std::cout << "Decrypting file...\n";
            context.decrypt(encryptedPath, decryptedPath).get();
            std::cout << "Decryption finished.\n";

            std::ifstream decryptedFile(
                decryptedPath,
                std::ios::binary
            );

            if (!decryptedFile) {
                std::cout << "Cannot open decrypted file: FAIL\n";
                continue;
            }

            type decrypted{
                std::istreambuf_iterator<char>(decryptedFile),
                std::istreambuf_iterator<char>()
            };

            decryptedFile.close();

            std::cout << "Original size: "
                      << original.size() << " bytes\n";

            std::cout << "Decrypted size: "
                      << decrypted.size() << " bytes\n";

            std::cout << "File restored: "
                      << (original == decrypted ? "OK" : "FAIL")
                      << '\n';
        }
    }
    catch (const std::exception& e) {
        std::cout << "File encryption/decryption: ERROR: "
                  << e.what() << '\n';
    }
    catch (...) {
        std::cout << "File encryption/decryption: UNKNOWN ERROR\n";
    }
}

void runPoint7Demo()
{
    std::cout << "\n========== POINT 7 ==========\n";

    testRandomArrays7();
    testCipherModes7();
    testPaddingModes7();

    testFileEncryption7("tests_file/test.txt", CipherMode::ECB);
    testFileEncryption7("tests_file/test_png_kripta.jpg", CipherMode::CBC);
    testFileEncryption7("tests_file/allocator_red_black_tree_tests.cpp",CipherMode::PCBC);
    testFileEncryption7("tests_file/test_mp3_kripta2.mp3", CipherMode::CFB);
    testFileEncryption7("tests_file/allocator_buddies_system.cpp", CipherMode::OFB);
    testFileEncryption7("tests_file/allocator_buddies_system.cpp", CipherMode::CFB);
    testFileEncryption7("tests_file/test_video_kripta2.MP4", CipherMode::CTR);
}