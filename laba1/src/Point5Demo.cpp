#include <iostream>
#include <iomanip>
#include <utility>
#include <vector>
#include <fstream>
#include <iterator>
#include <cstdio>
#include <exception>

#include "Point5Demo.h"
#include "DES/DES.h"
#include <random>
#include <future>
#include "CryptoContext.h"

void printHex(const type& data)
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

void testRandomArrays()
{
    std::cout << "\nRandom arrays test (DES + ECB + PKCS7)\n";

    DES des;

    type key = {
        0x13, 0x34, 0x57, 0x79,
        0x9B, 0xBC, 0xDF, 0xF1
    };

    des.setKey(key);

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, 255);

    const std::vector<size_t> lengths = {
        0, 1, 7, 8, 9, 15, 16, 17, 32, 64, 100
    };

    for (size_t length : lengths) {
        type original(length);

        for (uint8_t& byte : original) {
            byte = static_cast<uint8_t>(distribution(generator));
        }

        CryptoContext context(
            des,
            key,
            CipherMode::ECB,
            PaddingMode::PKCS7
        );

        try {
            type encrypted = context.encrypt(original).get();
            type decrypted = context.decrypt(encrypted).get();

            std::cout << "Length: " << length
                      << " bytes — "
                      << (decrypted == original ? "OK" : "FAIL")
                      << '\n';
        }
        catch (...) {
            std::cout << "Length: " << length << " bytes — ERROR\n";
        }
    }
}

void testCipherModes()
{
    std::cout << "\nCipher modes test (DES + PKCS7)\n";

    const type key = {
        0x13, 0x34, 0x57, 0x79,
        0x9B, 0xBC, 0xDF, 0xF1
    };

    // последний байт delta нечетный — это требуется реализацией RANDOM_DELTA.
    const type iv = {
        0x01, 0x23, 0x45, 0x67,
        0x00, 0x00, 0x00, 0x01
    };

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, 255);

    // создаем случайный массив длиной 37 байт.
    type original(37);

    for (uint8_t& byte : original) {
        byte = static_cast<uint8_t>(distribution(generator));
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

    for (const auto& [mode, name] : modes) {
        try {
            const type currentIV =
                mode == CipherMode::ECB ? type{} : iv;

            DES des;

            CryptoContext context(
                des,
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


void testPaddingModes()
{
    std::cout << "\nPadding modes test (DES + ECB)\n";

    const type key = {
        0x13, 0x34, 0x57, 0x79,
        0x9B, 0xBC, 0xDF, 0xF1
    };

    // 13 байт, последний байт не равен нулю.
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

    for (const auto& [padding, name] : paddings) {
        try {
            DES des;
            des.setKey(key);

            CryptoContext context(
                des,
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

void testFileEncryption(
    const std::string& inputPath,
    CipherMode mode
)
{
    std::cout << "\nFile: " << inputPath << '\n';

    const type key = {
        0x13, 0x34, 0x57, 0x79,
        0x9B, 0xBC, 0xDF, 0xF1
    };

    const type iv = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    };

    const std::string encryptedPath = inputPath + ".enc";
    const std::string decryptedPath = inputPath + ".dec";

    try
    {
        // читаем исходный файл в бинарном режиме.
        std::ifstream inputFile(inputPath, std::ios::binary);

        if (!inputFile)
        {
            std::cout << "Cannot open input file: FAIL\n";
            return;
        }

        type original{
            std::istreambuf_iterator<char>(inputFile),
            std::istreambuf_iterator<char>()
        };

        inputFile.close();

        // создаём контекст шифрования.
        DES des;
        CryptoContext context(
            des,
            key,
            mode,
            PaddingMode::PKCS7,
            iv
        );

        // шифруем и расшифровываем файл.
        std::cout << "Encrypting file...\n";
        context.encrypt(inputPath, encryptedPath).get();
        std::cout << "Encryption finished.\n";

        std::cout << "Decrypting file...\n";
        context.decrypt(encryptedPath, decryptedPath).get();
        std::cout << "Decryption finished.\n";

        // читаем восстановленный файл.
        std::ifstream decryptedFile(
            decryptedPath,
            std::ios::binary
        );

        if (!decryptedFile)
        {
            std::cout << "Cannot open decrypted file: FAIL\n";
            return;
        }

        type decrypted{
            std::istreambuf_iterator<char>(decryptedFile),
            std::istreambuf_iterator<char>()
        };

        std::cout << "Original size: "
                  << original.size() << " bytes\n";

        std::cout << "Decrypted size: "
                  << decrypted.size() << " bytes\n";

        std::cout << "File restored: "
                  << (original == decrypted ? "OK" : "FAIL")
                  << '\n';
    }
    catch (const std::exception& e)
    {
        std::cout << "File encryption/decryption: ERROR: "
                  << e.what() << '\n';
    }
    catch (Error e)
    {
        std::cout << "File encryption/decryption: ERROR, code = "
                << static_cast<int>(e) << '\n';
    }
    catch (...)
    {
        std::cout << "File encryption/decryption: UNKNOWN ERROR\n";
    }
}



void runPoint5Demo()
{
    std::cout << "\n========== POINT 5 ==========\n";
    std::cout << "\nDES known-answer test\n";

    type key = {
        0x13, 0x34, 0x57, 0x79,
        0x9B, 0xBC, 0xDF, 0xF1
    };

    type plaintext = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    };

    type expected = {
        0x85, 0xE8, 0x13, 0x54,
        0x0F, 0x0A, 0xB4, 0x05
    };

    DES des;
    des.setKey(key);

    type encrypted = des.encrypt(plaintext);
    type decrypted = des.decrypt(encrypted);

    std::cout << "Plaintext:  ";
    printHex(plaintext);

    std::cout << "Encrypted:  ";
    printHex(encrypted);

    std::cout << "Expected:   ";
    printHex(expected);

    std::cout << "Decrypted:  ";
    printHex(decrypted);

    std::cout << "Encryption: "
              << (encrypted == expected ? "OK" : "FAIL")
              << '\n';

    std::cout << "Decryption: "
              << (decrypted == plaintext ? "OK" : "FAIL")
              << '\n';

    testRandomArrays();
    testCipherModes();
    testPaddingModes();

    testFileEncryption("tests_file/test.txt", CipherMode::ECB);


}