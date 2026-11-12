#include "PolynomialArithmetic.h"
#include "Rijndael/Rijndael.h"
#include "Rijndael/RijndaelKeyExpansion.h"
#include "CryptoContext.h"
#include "Errors.h"

#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <cstdint>
#include <random>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <stdexcept>
#include <iomanip>

namespace fs = std::filesystem;

int passed = 0;
int failed = 0;

void check(const std::string& name, bool result) {
    if (result) {
        passed++;
    }
    else {
        std::cout << "[FAIL] " << name << '\n';
        failed++;
    }
}

void printHex(const type& data) {
    for (type_8 byte : data) {
        std::cout << std::uppercase << std::hex
                  << std::setw(2) << std::setfill('0')
                  << static_cast<int>(byte) << ' ';
    }

    std::cout << std::dec << '\n';
}

void printHexPrefix(const type& data, size_t count = 16) {
    size_t limit = std::min(data.size(), count);

    for (size_t i = 0; i < limit; ++i) {
        std::cout << std::uppercase << std::hex
                  << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << ' ';
    }

    std::cout << std::dec;

    if (data.size() > limit) {
        std::cout << "...";
    }

    std::cout << '\n';
}

void printHexValue(type_8 value) {
    std::cout << "0x"
              << std::uppercase << std::hex
              << std::setw(2) << std::setfill('0')
              << static_cast<int>(value)
              << std::dec << '\n';
}

void printResult(const std::string& name, bool success) {
    std::cout << name << ": "
              << (success ? "OK" : "FAIL") << '\n';

    if (success) {
        passed++;
    }
    else {
        failed++;
    }
}

template <typename Function>
void checkThrows(const std::string& name, Function function) {
    try {
        function();
        std::cout << name
                  << ": expected exception, but none was thrown - FAIL\n";
        failed++;
    }
    catch (Error) {
        std::cout << name
                  << ": expected exception was thrown - OK\n";
        passed++;
    }
    catch (...) {
        std::cout << name
                  << ": unexpected exception type - FAIL\n";
        failed++;
    }
}

// Сравнение факторизаций без учёта порядка множителей
bool SameFactors(
    std::vector<BigPolynomial> actual,
    std::vector<BigPolynomial> expected
) {
    if (actual.size() != expected.size()) return false;

    for (const BigPolynomial& factor : expected) {
        auto it = std::find(actual.begin(), actual.end(), factor);

        if (it == actual.end()) return false;

        actual.erase(it);
    }

    return actual.empty();
}

void printBigPolynomial(const BigPolynomial& polynomial) {
    std::cout << "[";

    for (size_t i = 0; i < polynomial.size(); ++i) {
        if (i != 0) std::cout << ", ";
        std::cout << polynomial[i];
    }

    std::cout << "]";
}

void printFactorization(const std::vector<BigPolynomial>& factors) {
    if (factors.empty()) {
        std::cout << "1\n";
        return;
    }

    for (size_t i = 0; i < factors.size(); ++i) {
        if (i != 0) std::cout << " * ";
        printBigPolynomial(factors[i]);
    }

    std::cout << '\n';
}

// ==================== POINT 1 ====================

void testAddition() {
    struct Test {
        type_8 a;
        type_8 b;
        type_8 expected;
    };

    const std::vector<Test> tests = {
        {0x57, 0x83, 0xD4},
        {0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0x00}
    };

    for (const auto& test : tests) {
        type_8 actual =
            PolynomialArithmetic::AddPolynomial(test.a, test.b);

        std::cout << "\nCondition: ";
        printHexValue(test.a);

        std::cout << " + ";
        printHexValue(test.b);

        std::cout << "Expected: ";
        printHexValue(test.expected);

        std::cout << "Actual:   ";
        printHexValue(actual);

        printResult("Result", actual == test.expected);
    }
}

// ==================== POINT 2 ====================

void testMultiplication() {
    struct Test {
        type_8 a;
        type_8 b;
        type_8 modulus;
        type_8 expected;
    };

    const std::vector<Test> tests = {
        {0x57, 0x83, 0x1B, 0xC1},
        {0x53, 0x00, 0x1B, 0x00},
        {0x53, 0x01, 0x1B, 0x53},
        {0x80, 0x02, 0x1B, 0x1B}
    };

    for (const auto& test : tests) {
        type_8 actual = PolynomialArithmetic::MultiplyPolynomial(
            test.a, test.b, test.modulus
        );

        std::cout << "\nCondition: ";
        printHexValue(test.a);

        std::cout << " * ";
        printHexValue(test.b);

        std::cout << "Modulo: ";
        printHexValue(test.modulus);

        std::cout << "Expected: ";
        printHexValue(test.expected);

        std::cout << "Actual:   ";
        printHexValue(actual);

        printResult("Result", actual == test.expected);
    }
}

// ==================== POINT 3 ====================

void testInverse() {
    const type_8 value = 0x53;
    const type_8 modulus = 0x1B;
    const type_8 expected = 0xCA;

    type_8 actual =
        PolynomialArithmetic::InversePolynomial(value, modulus);

    std::cout << "\nCondition: find multiplicative inverse of ";
    printHexValue(value);

    std::cout << "Field modulus: ";
    printHexValue(modulus);

    std::cout << "Expected inverse: ";
    printHexValue(expected);

    std::cout << "Actual inverse:   ";
    printHexValue(actual);

    printResult("Inverse calculation", actual == expected);

    type_8 product =
        PolynomialArithmetic::MultiplyPolynomial(value, actual, modulus);

    std::cout << "\nCheck: a * inverse(a) = 1\n";

    std::cout << "a: ";
    printHexValue(value);

    std::cout << "inverse(a): ";
    printHexValue(actual);

    std::cout << "Expected product: 0x01\n";

    std::cout << "Actual product:   ";
    printHexValue(product);

    printResult("Multiplicative identity", product == 1);

    type_8 oneInverse =
        PolynomialArithmetic::InversePolynomial(0x01, modulus);

    std::cout << "\nCondition: inverse of 0x01\n";
    std::cout << "Expected: 0x01\n";
    std::cout << "Actual:   ";
    printHexValue(oneInverse);

    printResult("Inverse of one", oneInverse == 0x01);

    std::cout << "\nCondition: inverse of zero must throw an exception\n";

    checkThrows("Zero has no inverse", []() {
        PolynomialArithmetic::InversePolynomial(0x00, 0x1B);
    });
}

// ==================== POINT 4 ====================

void testIrreducibility() {
    struct Test {
        type_8 polynomial;
        bool expected;
    };

    const std::vector<Test> tests = {
        {0x1B, true},
        {0x1D, true},
        {0x01, false},
        {0x00, false}
    };

    for (const auto& test : tests) {
        bool actual =
            PolynomialArithmetic::IsIrreducible(test.polynomial);

        std::cout << "\nPolynomial: ";
        printHexValue(test.polynomial);

        std::cout << "Expected: "
                  << (test.expected ? "irreducible" : "reducible") << '\n';

        std::cout << "Actual:   "
                  << (actual ? "irreducible" : "reducible") << '\n';

        printResult("Result", actual == test.expected);
    }
}

// ==================== POINT 5 ====================

void testGenerateIrreduciblePolynomials() {
    const std::vector<type_8> expected = {
        0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F,
        0x4D, 0x5F, 0x63, 0x65, 0x69, 0x71,
        0x77, 0x7B, 0x87, 0x8B, 0x8D, 0x9F,
        0xA3, 0xA9, 0xB1, 0xBD, 0xC3, 0xCF,
        0xD7, 0xDD, 0xE7, 0xF3, 0xF5, 0xF9
    };

    const std::vector<type_8> actual =
        PolynomialArithmetic::GenerateAllIrreduciblePolynomials();

    std::cout << "\nExpected number of irreducible polynomials: "
              << expected.size() << '\n';

    std::cout << "Actual number of irreducible polynomials:   "
              << actual.size() << '\n';

    printResult(
        "Number of generated polynomials",
        actual.size() == expected.size()
    );

    std::cout << "\nExpected polynomials:\n";

    for (type_8 value : expected) {
        std::cout << "  ";
        printHexValue(value);
    }

    std::cout << "\nGenerated polynomials:\n";

    for (type_8 value : actual) {
        std::cout << "  ";
        printHexValue(value);
    }

    printResult(
        "Generated values match expected values",
        actual == expected
    );
}

// ==================== POINT 6 ====================

void testFactorization() {
    struct Test {
        const char* name;
        big_type polynomial;
        big_type modulus;
        std::vector<BigPolynomial> expected;
    };

    const std::vector<Test> tests = {
        {"x^2 + x + 1", 0b111, 0b111, {{2, 1}, {3, 1}}},
        {"x^2 + 1",     0b101, 0b111, {{1, 1}, {1, 1}}},
        {"x",           0b10,  0b111, {{0, 1}}},
        {"1",           0b1,   0b111, {}}
    };

    for (const auto& test : tests) {
        std::vector<BigPolynomial> actual =
            PolynomialArithmetic::FactorizePolynomial(
                test.polynomial, test.modulus
            );

        std::cout << "\nPolynomial: " << test.name << '\n';

        std::cout << "Polynomial bit representation: "
                  << test.polynomial << '\n';

        std::cout << "Field modulus: "
                  << test.modulus << '\n';

        std::cout << "Expected factorization: ";
        printFactorization(test.expected);

        std::cout << "Actual factorization:   ";
        printFactorization(actual);

        printResult(
            "Factorization",
            SameFactors(actual, test.expected)
        );
    }

    std::cout << "\nCondition: factorization of zero polynomial must throw\n";

    checkThrows("Zero polynomial cannot be factorized", []() {
        PolynomialArithmetic::FactorizePolynomial(0, 0b111);
    });

    std::cout << "\nCondition: reducible field modulus must be rejected\n";

    checkThrows("Reducible field modulus is rejected", []() {
        PolynomialArithmetic::FactorizePolynomial(0b111, 0b101);
    });
}

// ==================== POINT 7 ====================

void testExceptions() {
    std::cout << "\nCondition: multiplication with reducible modulus 0x01\n";

    checkThrows("Multiplication with reducible modulus", []() {
        PolynomialArithmetic::MultiplyPolynomial(0x57, 0x83, 0x01);
    });

    std::cout << "\nCondition: inverse with reducible modulus 0x01\n";

    checkThrows("Inverse with reducible modulus", []() {
        PolynomialArithmetic::InversePolynomial(0x53, 0x01);
    });
}

// ==================== RIJNDAEL ====================

void testRijndaelConfiguration(
    size_t blockSize,
    size_t keySize,
    type_8 modulus
) {
    Rijndael* cipherPtr = nullptr;

    RijndaelKeyExpansion keyExpansion(
        keySize,
        blockSize,
        modulus,
        [&cipherPtr](const type& input) {
            if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
            return cipherPtr->subBytes(input);
        }
    );

    Rijndael cipher(blockSize, keySize, modulus, keyExpansion);
    cipherPtr = &cipher;

    type key;

    for (size_t i = 0; i < keySize / 8; i++) {
        key.push_back(static_cast<type_8>(i * 7 + 3));
    }

    type block;

    for (size_t i = 0; i < blockSize / 8; i++) {
        block.push_back(static_cast<type_8>(i * 11 + 5));
    }

    const size_t Nk = keySize / 32;
    const size_t Nb = blockSize / 32;
    const size_t Nr = std::max(Nk, Nb) + 6;

    std::cout << "\n----------------------------------------\n";
    std::cout << "Block size: " << blockSize << " bits\n";
    std::cout << "Key size:   " << keySize << " bits\n";

    std::cout << "Polynomial: ";
    printHexValue(modulus);

    std::cout << "\nKey:\n";
    printHex(key);

    std::cout << "Plaintext:\n";
    printHex(block);

    std::vector<type> roundKeys =
        keyExpansion.generateRoundKeys(key);

    std::cout << "\nExpected number of round keys: "
              << Nr + 1 << '\n';

    std::cout << "Actual number of round keys:   "
              << roundKeys.size() << '\n';

    printResult(
        "Round key count",
        roundKeys.size() == Nr + 1
    );

    bool correctRoundKeySizes = true;

    for (const type& roundKey : roundKeys) {
        if (roundKey.size() != blockSize / 8) {
            correctRoundKeySizes = false;
            break;
        }
    }

    std::cout << "Expected round key size: "
              << blockSize / 8 << " bytes\n";

    std::cout << "Actual round key sizes: ";

    for (const type& roundKey : roundKeys) {
        std::cout << roundKey.size() << ' ';
    }

    std::cout << "bytes\n";

    printResult("Round key sizes", correctRoundKeySizes);

    std::cout << "\nExpected getBlockSize(): "
              << blockSize / 8 << " bytes\n";

    std::cout << "Actual getBlockSize():   "
              << cipher.getBlockSize() << " bytes\n";

    printResult(
        "getBlockSize()",
        cipher.getBlockSize() == blockSize / 8
    );

    cipher.setKey(key);

    type encrypted = cipher.encrypt(block);
    type decrypted = cipher.decrypt(encrypted);

    std::cout << "\nEncrypted:\n";
    printHex(encrypted);

    std::cout << "Decrypted:\n";
    printHex(decrypted);

    std::cout << "Expected decrypted data:\n";
    printHex(block);

    printResult(
        "Decryption restores original block",
        decrypted == block
    );

    printResult(
        "Encrypted block size",
        encrypted.size() == blockSize / 8
    );

    type encryptedAgain = cipher.encrypt(block);

    std::cout << "\nDeterministic encryption check:\n";

    std::cout << "First ciphertext:\n";
    printHex(encrypted);

    std::cout << "Second ciphertext:\n";
    printHex(encryptedAgain);

    printResult(
        "Encryption is deterministic",
        encryptedAgain == encrypted
    );
}

void testRijndaelAllSizes() {
    std::vector<size_t> sizes = {128, 192, 256};

    for (size_t blockSize : sizes) {
        for (size_t keySize : sizes) {
            testRijndaelConfiguration(blockSize, keySize, 0x1B);
        }
    }
}

// ==================== AES-128 KNOWN ANSWER ====================

void testRijndaelKnownVector() {
    Rijndael* cipherPtr = nullptr;

    RijndaelKeyExpansion keyExpansion(
        128,
        128,
        0x1B,
        [&cipherPtr](const type& input) {
            if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
            return cipherPtr->subBytes(input);
        }
    );

    Rijndael cipher(128, 128, 0x1B, keyExpansion);
    cipherPtr = &cipher;

    type key = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    type plaintext = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF
    };

    type expected = {
        0x69, 0xC4, 0xE0, 0xD8,
        0x6A, 0x7B, 0x04, 0x30,
        0xD8, 0xCD, 0xB7, 0x80,
        0x70, 0xB4, 0xC5, 0x5A
    };

    cipher.setKey(key);

    type encrypted = cipher.encrypt(plaintext);
    type decrypted = cipher.decrypt(encrypted);

    std::cout << "\nAES-128 known-answer test\n";

    std::cout << "Key:\n";
    printHex(key);

    std::cout << "Plaintext:\n";
    printHex(plaintext);

    std::cout << "Expected ciphertext:\n";
    printHex(expected);

    std::cout << "Actual ciphertext:\n";
    printHex(encrypted);

    std::cout << "Decrypted plaintext:\n";
    printHex(decrypted);

    printResult("Encryption", encrypted == expected);
    printResult("Decryption", decrypted == plaintext);
}

// ==================== BOUNDARY BLOCKS ====================

void testRijndaelBoundaryBlocks() {
    Rijndael* cipherPtr = nullptr;

    RijndaelKeyExpansion keyExpansion(
        128, 128, 0x1B,
        [&cipherPtr](const type& input) {
            if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
            return cipherPtr->subBytes(input);
        }
    );

    Rijndael cipher(128, 128, 0x1B, keyExpansion);
    cipherPtr = &cipher;

    type key(16, 0x00);
    cipher.setKey(key);

    type zeroBlock(16, 0x00);
    type ffBlock(16, 0xFF);
    type sequentialBlock;

    for (size_t i = 0; i < 16; i++) {
        sequentialBlock.push_back(static_cast<type_8>(i));
    }

    auto showRoundTrip = [&](const std::string& name, const type& input) {
        type encrypted = cipher.encrypt(input);
        type decrypted = cipher.decrypt(encrypted);

        std::cout << "\n" << name << '\n';

        std::cout << "Original:\n";
        printHex(input);

        std::cout << "Encrypted:\n";
        printHex(encrypted);

        std::cout << "Decrypted:\n";
        printHex(decrypted);

        printResult(
            name + " round-trip",
            decrypted == input
        );

        return encrypted;
    };

    type encryptedZero =
        showRoundTrip("All-zero block", zeroBlock);

    type encryptedFF =
        showRoundTrip("All-0xFF block", ffBlock);

    showRoundTrip("Sequential block", sequentialBlock);

    std::cout << "\nDifferent plaintexts must produce different ciphertexts\n";

    std::cout << "Zero block ciphertext:\n";
    printHex(encryptedZero);

    std::cout << "0xFF block ciphertext:\n";
    printHex(encryptedFF);

    printResult(
        "Different plaintexts produce different ciphertexts",
        encryptedZero != encryptedFF
    );
}
// ==================== REPEATED KEY SETTING ====================

void testRijndaelRepeatedKeys() {
    Rijndael* cipherPtr = nullptr;

    RijndaelKeyExpansion keyExpansion(
        128, 128, 0x1B,
        [&cipherPtr](const type& input) {
            if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
            return cipherPtr->subBytes(input);
        }
    );

    Rijndael cipher(128, 128, 0x1B, keyExpansion);
    cipherPtr = &cipher;

    type key1(16, 0x01);
    type key2(16, 0x02);
    type block(16, 0x55);

    std::cout << "\nPlaintext:\n";
    printHex(block);

    cipher.setKey(key1);
    type encrypted1 = cipher.encrypt(block);

    std::cout << "\nFirst key (all bytes 0x01):\n";
    printHex(key1);

    std::cout << "Ciphertext with first key:\n";
    printHex(encrypted1);

    cipher.setKey(key2);
    type encrypted2 = cipher.encrypt(block);

    std::cout << "\nSecond key (all bytes 0x02):\n";
    printHex(key2);

    std::cout << "Ciphertext with second key:\n";
    printHex(encrypted2);

    printResult(
        "Different keys produce different ciphertexts",
        encrypted1 != encrypted2
    );

    cipher.setKey(key1);
    type encryptedAgain = cipher.encrypt(block);

    std::cout << "\nCiphertext after setting first key again:\n";
    printHex(encryptedAgain);

    printResult(
        "Returning to first key restores original result",
        encrypted1 == encryptedAgain
    );

    type decrypted = cipher.decrypt(encryptedAgain);

    std::cout << "Decrypted data:\n";
    printHex(decrypted);

    printResult(
        "Decryption after changing key",
        decrypted == block
    );
}

// ==================== INVALID INPUTS ====================

void testRijndaelInvalidInputs() {
    Rijndael* cipherPtr = nullptr;

    RijndaelKeyExpansion keyExpansion(
        128, 128, 0x1B,
        [&cipherPtr](const type& input) {
            if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
            return cipherPtr->subBytes(input);
        }
    );

    std::cout << "\nExpected errors for invalid constructor arguments:\n";

    checkThrows("Block size = 64 bits", [&]() {
        Rijndael invalidCipher(64, 128, 0x1B, keyExpansion);
    });

    checkThrows("Key size = 64 bits", [&]() {
        Rijndael invalidCipher(128, 64, 0x1B, keyExpansion);
    });

    checkThrows("Reducible modulus = 0x01", [&]() {
        Rijndael invalidCipher(128, 128, 0x01, keyExpansion);
    });

    Rijndael cipher(128, 128, 0x1B, keyExpansion);
    cipherPtr = &cipher;

    std::cout << "\nExpected errors before setting a key:\n";

    checkThrows("Encrypt without key", [&]() {
        cipher.encrypt(type(16, 0x00));
    });

    checkThrows("Decrypt without key", [&]() {
        cipher.decrypt(type(16, 0x00));
    });

    std::cout << "\nExpected errors for incorrect input sizes:\n";

    checkThrows("setKey with 15 bytes instead of 16", [&]() {
        cipher.setKey(type(15, 0x00));
    });

    cipher.setKey(type(16, 0x00));

    checkThrows("Encrypt with 15 bytes instead of 16", [&]() {
        cipher.encrypt(type(15, 0x00));
    });

    checkThrows("Decrypt with 17 bytes instead of 16", [&]() {
        cipher.decrypt(type(17, 0x00));
    });
}

// ==================== CUSTOM MODULUS ====================

void testRijndaelCustomModulus() {
    Rijndael* cipherPtr = nullptr;

    const type_8 modulus = 0x1D;

    RijndaelKeyExpansion keyExpansion(
        128, 128, modulus,
        [&cipherPtr](const type& input) {
            if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
            return cipherPtr->subBytes(input);
        }
    );

    Rijndael cipher(128, 128, modulus, keyExpansion);
    cipherPtr = &cipher;

    type key(16, 0x37);
    type block(16, 0xA5);

    cipher.setKey(key);

    type encrypted = cipher.encrypt(block);
    type decrypted = cipher.decrypt(encrypted);

    std::cout << "\nField modulus: ";
    printHexValue(modulus);

    std::cout << "Key:\n";
    printHex(key);

    std::cout << "Original block:\n";
    printHex(block);

    std::cout << "Encrypted block:\n";
    printHex(encrypted);

    std::cout << "Decrypted block:\n";
    printHex(decrypted);

    printResult(
        "Round-trip with custom irreducible modulus",
        decrypted == block
    );
}

// ==================== CRYPTO CONTEXT ====================

// Генерация псевдослучайных данных
type generateRandomData(size_t size) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dist(0, 255);

    type data(size);

    for (size_t i = 0; i < size; i++) {
        data[i] = static_cast<type_8>(dist(gen));
    }

    return data;
}

type generateKey(size_t keySize) {
    return generateRandomData(keySize / 8);
}

// Для RANDOM_DELTA последняя часть IV (delta) должна оканчиваться нечётным байтом.
type generateIV(size_t blockSize) {
    type iv(blockSize / 8, 0);
    iv.back() = 1;
    return iv;
}

std::string getModeName(CipherMode mode) {
    switch (mode) {
        case CipherMode::ECB: return "ECB";
        case CipherMode::CBC: return "CBC";
        case CipherMode::PCBC: return "PCBC";
        case CipherMode::CFB: return "CFB";
        case CipherMode::OFB: return "OFB";
        case CipherMode::CTR: return "CTR";
        case CipherMode::RANDOM_DELTA: return "RANDOM_DELTA";
    }

    return "UNKNOWN";
}

std::string getPaddingName(PaddingMode padding) {
    switch (padding) {
        case PaddingMode::Zeros: return "Zeros";
        case PaddingMode::ANSI_X923: return "ANSI_X923";
        case PaddingMode::PKCS7: return "PKCS7";
        case PaddingMode::ISO10126: return "ISO10126";
    }

    return "UNKNOWN";
}

// Проверка одного целевого сценария CryptoContext.
// Подробности выводятся только при ошибке.
bool testRandomData(
    size_t blockSize,
    size_t keySize,
    type_8 modulus,
    CipherMode mode,
    PaddingMode padding,
    size_t dataSize
) {
    try {
        Rijndael* cipherPtr = nullptr;

        RijndaelKeyExpansion keyExpansion(
            keySize,
            blockSize,
            modulus,
            [&cipherPtr](const type& input) {
                if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
                return cipherPtr->subBytes(input);
            }
        );

        Rijndael cipher(blockSize, keySize, modulus, keyExpansion);
        cipherPtr = &cipher;

        type key = generateKey(keySize);
        type iv = generateIV(blockSize);
        type data = generateRandomData(dataSize);

        // Для Zeros последний байт должен быть ненулевым,
        // иначе при снятии дополнения невозможно отличить его от padding.
        if (padding == PaddingMode::Zeros && !data.empty()) {
            data.back() = 1;
        }

        CryptoContext context(cipher, key, mode, padding, iv);

        type encrypted = context.encrypt(data).get();
        type decrypted = context.decrypt(encrypted).get();

        return decrypted == data;
    }
    catch (const std::exception& e) {
        std::cout << "[ERROR] " << getModeName(mode)
                  << ", block=" << blockSize
                  << ", key=" << keySize
                  << ", polynomial=0x" << std::hex
                  << static_cast<int>(modulus) << std::dec
                  << ", data size=" << dataSize
                  << ": " << e.what() << '\n';
        return false;
    }
    catch (...) {
        std::cout << "[ERROR] " << getModeName(mode)
                  << ", block=" << blockSize
                  << ", key=" << keySize
                  << ", polynomial=0x" << std::hex
                  << static_cast<int>(modulus) << std::dec
                  << ", data size=" << dataSize
                  << ": unknown exception\n";
        return false;
    }
}

// 7 сценариев: каждый режим проверяется один раз,
// а размеры блока, ключа и многочлены распределены между сценариями.
void testCryptoContextRandomData() {
    struct TestCase {
        size_t blockSize;
        size_t keySize;
        type_8 modulus;
        CipherMode mode;
        size_t dataSize;
    };

    const std::vector<TestCase> tests = {
        // Ровно один блок
        {128, 128, 0x1B, CipherMode::ECB,          16},

        // Несколько блоков, другая конфигурация
        {192, 256, 0x1D, CipherMode::CBC,          49},
        {256, 192, 0x2B, CipherMode::PCBC,         97},

        // Очень короткие данные
        {128, 256, 0x1D, CipherMode::CFB,           1},

        // Данные меньше блока
        {192, 128, 0x2B, CipherMode::OFB,          23},

        // Длина не кратна размеру блока
        {256, 256, 0x1B, CipherMode::CTR,          33},

        // Пустые данные
        {128, 192, 0x2B, CipherMode::RANDOM_DELTA,  0}
    };

    for (const TestCase& test : tests) {
        bool success = testRandomData(
            test.blockSize,
            test.keySize,
            test.modulus,
            test.mode,
            PaddingMode::PKCS7,
            test.dataSize
        );

        check(
            "CryptoContext " + getModeName(test.mode),
            success
        );
    }
}

// Каждый вариант дополнения проверяется на отдельном граничном размере данных.
void testCryptoContextPadding() {
    struct TestCase {
        PaddingMode padding;
        size_t dataSize;
    };

    const std::vector<TestCase> tests = {
        {PaddingMode::Zeros,     16}, // ровно один блок
        {PaddingMode::ANSI_X923,  1}, // один байт
        {PaddingMode::PKCS7,     17}, // на один байт больше блока
        {PaddingMode::ISO10126,  15}  // на один байт меньше блока
    };

    for (const TestCase& test : tests) {
        bool success = testRandomData(
            128,
            128,
            0x1B,
            CipherMode::CBC,
            test.padding,
            test.dataSize
        );

        check(
            "CryptoContext padding " + getPaddingName(test.padding),
            success
        );
    }
}

// ==================== FILES ====================

// Чтение файла в байтовый вектор
type readFile(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);

    if (!file) {
        throw std::runtime_error("Cannot open file: " + path.string());
    }

    std::vector<char> buffer(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    type data;
    data.reserve(buffer.size());

    for (unsigned char byte : buffer) {
        data.push_back(byte);
    }

    return data;
}

void testFileEncryption(
    const std::string& inputFile,
    CipherMode mode
) {
    const size_t blockSize = 128;
    const size_t keySize = 128;
    const type_8 modulus = 0x1B;

    fs::path inputPath = inputFile;
    fs::path outputDirectory = inputPath.parent_path() / "results";

    try {
        fs::create_directories(outputDirectory);

        std::string suffix = getModeName(mode);

        fs::path encryptedPath =
            outputDirectory /
            (inputPath.filename().string() + "_" + suffix + ".enc");

        fs::path decryptedPath =
            outputDirectory /
            (inputPath.filename().string() + "_" + suffix + ".dec");

        type originalData = readFile(inputPath);

        Rijndael* cipherPtr = nullptr;

        RijndaelKeyExpansion keyExpansion(
            keySize,
            blockSize,
            modulus,
            [&cipherPtr](const type& input) {
                if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
                return cipherPtr->subBytes(input);
            }
        );

        Rijndael cipher(blockSize, keySize, modulus, keyExpansion);
        cipherPtr = &cipher;

        type key = generateKey(keySize);
        type iv = generateIV(blockSize);

        CryptoContext context(
            cipher,
            key,
            mode,
            PaddingMode::PKCS7,
            iv
        );

        context.encrypt(
            inputPath.string(),
            encryptedPath.string()
        ).get();

        context.decrypt(
            encryptedPath.string(),
            decryptedPath.string()
        ).get();

        type decryptedData = readFile(decryptedPath);

        check(
            "File " + inputPath.filename().string() +
            " | " + suffix,
            decryptedData == originalData
        );
    }
    catch (const std::exception& e) {
        std::cout << "[ERROR] File " << inputPath.filename().string()
                  << " | " << getModeName(mode)
                  << ": " << e.what() << '\n';

        check(
            "File " + inputPath.filename().string() +
            " | " + getModeName(mode),
            false
        );
    }
    catch (...) {
        std::cout << "[ERROR] File " << inputPath.filename().string()
                  << " | " << getModeName(mode)
                  << ": unknown exception\n";

        check(
            "File " + inputPath.filename().string() +
            " | " + getModeName(mode),
            false
        );
    }
}

void testCryptoContextFiles() {
    testFileEncryption(
        "tests_file/test_mp3_kripta.ogg",
        CipherMode::ECB
    );

    testFileEncryption(
        "tests_file/test_png_kripta.jpg",
        CipherMode::CBC
    );

    testFileEncryption(
        "tests_file/allocator_red_black_tree_tests.cpp",
        CipherMode::PCBC
    );

    testFileEncryption(
        "tests_file/test_mp3_kripta2.mp3",
        CipherMode::CFB
    );

    testFileEncryption(
        "tests_file/allocator_buddies_system.cpp",
        CipherMode::OFB
    );

    testFileEncryption(
        "tests_file/allocator_buddies_system.cpp",
        CipherMode::CFB
    );

    testFileEncryption(
        "tests_file/test_video_kripta2.MOV",
        CipherMode::CTR
    );
}

// ==================== MAIN ====================

int main() {
    auto runSection = [](const std::string& title, auto function) {
        std::cout << "\n========== " << title << " ==========\n";

        int failedBefore = failed;

        function();

        std::cout << title << ": "
                  << (failed == failedBefore ? "OK" : "FAIL")
                  << '\n';
    };

    runSection("POINT 1 - ADDITION GF(2^8)", testAddition);
    runSection("POINT 2 - MULTIPLICATION GF(2^8)", testMultiplication);
    runSection("POINT 3 - INVERSE GF(2^8)", testInverse);
    runSection("POINT 4 - IRREDUCIBILITY", testIrreducibility);

    runSection(
        "POINT 5 - ALL IRREDUCIBLE POLYNOMIALS",
        testGenerateIrreduciblePolynomials
    );

    runSection(
        "POINT 6 - POLYNOMIAL FACTORIZATION",
        testFactorization
    );

    runSection("POINT 7 - EXCEPTION CHECKS", testExceptions);

    runSection(
        "POINT 8 - RIJNDAEL: AES-128 KNOWN ANSWER",
        testRijndaelKnownVector
    );

    runSection(
        "POINT 9 - RIJNDAEL: ALL BLOCK AND KEY SIZES",
        testRijndaelAllSizes
    );

    runSection(
        "POINT 10 - RIJNDAEL: BOUNDARY BLOCKS",
        testRijndaelBoundaryBlocks
    );

    runSection(
        "POINT 11 - RIJNDAEL: REPEATED KEY SETTING",
        testRijndaelRepeatedKeys
    );

    runSection(
        "POINT 12 - RIJNDAEL: INVALID INPUTS",
        testRijndaelInvalidInputs
    );

    runSection(
        "POINT 13 - RIJNDAEL: CUSTOM FIELD MODULUS",
        testRijndaelCustomModulus
    );

    runSection(
        "POINT 14 - CRYPTO CONTEXT: RANDOM DATA",
        testCryptoContextRandomData
    );

    runSection(
        "POINT 15 - CRYPTO CONTEXT: PADDING EDGE CASES",
        testCryptoContextPadding
    );

    runSection(
        "POINT 16 - CRYPTO CONTEXT: FILES",
        testCryptoContextFiles
    );

    std::cout << "\n========== SUMMARY ==========\n";

    std::cout << "Passed: " << passed << '\n';
    std::cout << "Failed: " << failed << '\n';
    std::cout << "Total:  " << passed + failed << '\n';

    if (failed != 0) {
        std::cout << "Some tests FAILED.\n";
        return 1;
    }

    std::cout << "All registered tests PASSED.\n";

    return 0;
}