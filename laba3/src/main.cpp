
#include "PolynomialArithmetic.h"
#include "Rijndael/Rijndael.h"
#include "Rijndael/RijndaelKeyExpansion.h"

#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <cstdint>

int passed = 0;
int failed = 0;

void check(const std::string& name, bool result) {
    if (result) {
        std::cout << "[PASS] " << name << '\n';
        passed++;
    }
    else {
        std::cout << "[FAIL] " << name << '\n';
        failed++;
    }
}

template <typename Function>
void checkThrows(const std::string& name, Function function) {
    try {
        function();
        check(name, false);
    }
    catch (Error error) {
        check(name, true);
    }
    catch (...) {
        check(name, false);
    }
}

// Сравнение факторизаций без учёта порядка множителей
bool SameFactors(std::vector<BigPolynomial> actual, std::vector<BigPolynomial> expected) {
    if (actual.size() != expected.size()) return false;

    for (const BigPolynomial& factor : expected) {
        auto it = std::find(actual.begin(), actual.end(), factor);

        if (it == actual.end()) return false;

        actual.erase(it);
    }

    return actual.empty();
}

void testAddition() {
    std::cout << "\n1. ADDITION GF(2^8)\n";

    check("0x57 + 0x83 = 0xD4",
        PolynomialArithmetic::AddPolynomial(0x57, 0x83) == 0xD4);

    check("0x00 + 0x00 = 0x00",
        PolynomialArithmetic::AddPolynomial(0x00, 0x00) == 0x00);

    check("0xFF + 0xFF = 0x00",
        PolynomialArithmetic::AddPolynomial(0xFF, 0xFF) == 0x00);
}

void testMultiplication() {
    std::cout << "\n2. MULTIPLICATION GF(2^8)\n";

    check("0x57 * 0x83 = 0xC1",
        PolynomialArithmetic::MultiplyPolynomial(0x57, 0x83, 0x1B) == 0xC1);

    check("Multiplication by zero",
        PolynomialArithmetic::MultiplyPolynomial(0x53, 0x00, 0x1B) == 0x00);

    check("Multiplication by one",
        PolynomialArithmetic::MultiplyPolynomial(0x53, 0x01, 0x1B) == 0x53);

    check("0x80 * 0x02 = 0x1B",
        PolynomialArithmetic::MultiplyPolynomial(0x80, 0x02, 0x1B) == 0x1B);
}

void testInverse() {
    std::cout << "\n3. INVERSE GF(2^8)\n";

    type_8 inverse = PolynomialArithmetic::InversePolynomial(0x53, 0x1B);

    check("Inverse of 0x53 = 0xCA", inverse == 0xCA);

    check("0x53 * inverse(0x53) = 1",
        PolynomialArithmetic::MultiplyPolynomial(0x53, inverse, 0x1B) == 1);

    check("Inverse of 0x01 = 0x01",
        PolynomialArithmetic::InversePolynomial(0x01, 0x1B) == 0x01);

    checkThrows("Zero has no inverse", []() {
        PolynomialArithmetic::InversePolynomial(0x00, 0x1B);
    });
}

void testIrreducibility() {
    std::cout << "\n4. IRREDUCIBILITY CHECK\n";

    check("0x1B is irreducible",
        PolynomialArithmetic::IsIrreducible(0x1B));

    check("0x1D is irreducible",
        PolynomialArithmetic::IsIrreducible(0x1D));

    check("0x01 is reducible",
        !PolynomialArithmetic::IsIrreducible(0x01));

    check("0x00 is reducible",
        !PolynomialArithmetic::IsIrreducible(0x00));
}

void testGenerateIrreduciblePolynomials() {
    std::cout << "\n5. ALL IRREDUCIBLE POLYNOMIALS\n";

    std::vector<type_8> actual =
        PolynomialArithmetic::GenerateAllIrreduciblePolynomials();

    std::vector<type_8> expected = {
        0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F,
        0x4D, 0x5F, 0x63, 0x65, 0x69, 0x71,
        0x77, 0x7B, 0x87, 0x8B, 0x8D, 0x9F,
        0xA3, 0xA9, 0xB1, 0xBD, 0xC3, 0xCF,
        0xD7, 0xDD, 0xE7, 0xF3, 0xF5, 0xF9
    };

    check("Exactly 30 irreducible polynomials", actual.size() == 30);
    check("All generated polynomials match expected values", actual == expected);
}

void testFactorization() {
    std::cout << "\n6. POLYNOMIAL FACTORIZATION\n";

    // x^2 + x + 1 over GF(4)
    check("Factorization of x^2 + x + 1",
        SameFactors(
            PolynomialArithmetic::FactorizePolynomial(0b111, 0b111),
            { {2, 1}, {3, 1} }
        )
    );

    // x^2 + 1 = (x + 1)^2 over GF(4)
    check("Factorization of x^2 + 1",
        SameFactors(
            PolynomialArithmetic::FactorizePolynomial(0b101, 0b111),
            { {1, 1}, {1, 1} }
        )
    );

    // x
    check("Factorization of x",
        SameFactors(
            PolynomialArithmetic::FactorizePolynomial(0b10, 0b111),
            { {0, 1} }
        )
    );

    // 1 has no irreducible factors
    check("Factorization of 1",
        PolynomialArithmetic::FactorizePolynomial(0b1, 0b111).empty()
    );

    checkThrows("Zero polynomial cannot be factorized", []() {
        PolynomialArithmetic::FactorizePolynomial(0, 0b111);
    });

    checkThrows("Reducible field modulus is rejected", []() {
        PolynomialArithmetic::FactorizePolynomial(0b111, 0b101);
    });
}

void testExceptions() {
    std::cout << "\n7. EXCEPTION CHECKS\n";

    checkThrows("Multiplication with reducible modulus", []() {
        PolynomialArithmetic::MultiplyPolynomial(0x57, 0x83, 0x01);
    });

    checkThrows("Inverse with reducible modulus", []() {
        PolynomialArithmetic::InversePolynomial(0x53, 0x01);
    });
}

// Создание тестового набора Rijndael
void testRijndaelConfiguration(size_t blockSize, size_t keySize, type_8 modulus) {
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

    size_t Nk = keySize / 32;
    size_t Nb = blockSize / 32;
    size_t Nr = std::max(Nk, Nb) + 6;

    std::vector<type> roundKeys = keyExpansion.generateRoundKeys(key);

    check(
        "Correct number of round keys: block " + std::to_string(blockSize) +
        ", key " + std::to_string(keySize),
        roundKeys.size() == Nr + 1
    );

    bool correctRoundKeySizes = true;

    for (const type& roundKey : roundKeys) {
        if (roundKey.size() != blockSize / 8) {
            correctRoundKeySizes = false;
            break;
        }
    }

    check(
        "Correct round key sizes: block " + std::to_string(blockSize) +
        ", key " + std::to_string(keySize),
        correctRoundKeySizes
    );

    check(
        "Correct getBlockSize(): block " + std::to_string(blockSize),
        cipher.getBlockSize() == blockSize / 8
    );

    cipher.setKey(key);

    type encrypted = cipher.encrypt(block);
    type decrypted = cipher.decrypt(encrypted);

    check(
        "Encrypt/decrypt: block " + std::to_string(blockSize) +
        ", key " + std::to_string(keySize),
        decrypted == block
    );

    check(
        "Encrypted block has correct size",
        encrypted.size() == blockSize / 8
    );

    check(
        "Encryption is deterministic",
        cipher.encrypt(block) == encrypted
    );
}

void testRijndaelAllSizes() {
    std::cout << "\n8. RIJNDAEL: ALL BLOCK AND KEY SIZES\n";

    std::vector<size_t> sizes = {128, 192, 256};

    for (size_t blockSize : sizes) {
        for (size_t keySize : sizes) {
            testRijndaelConfiguration(blockSize, keySize, 0x1B);
        }
    }
}

void testRijndaelKnownVector() {
    std::cout << "\n9. RIJNDAEL: AES-128 KNOWN ANSWER TEST\n";

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

    check("AES-128 known encryption vector", encrypted == expected);

    check("AES-128 known decryption vector", cipher.decrypt(expected) == plaintext);
}

void testRijndaelBoundaryBlocks() {
    std::cout << "\n10. RIJNDAEL: BOUNDARY BLOCKS\n";

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

    type key(16, 0x00);
    cipher.setKey(key);

    type zeroBlock(16, 0x00);
    type ffBlock(16, 0xFF);
    type sequentialBlock;

    for (size_t i = 0; i < 16; i++) {
        sequentialBlock.push_back(static_cast<type_8>(i));
    }

    check("Zero block round-trip",
        cipher.decrypt(cipher.encrypt(zeroBlock)) == zeroBlock);

    check("0xFF block round-trip",
        cipher.decrypt(cipher.encrypt(ffBlock)) == ffBlock);

    check("Sequential block round-trip",
        cipher.decrypt(cipher.encrypt(sequentialBlock)) == sequentialBlock);

    check("Different plaintexts produce different ciphertexts",
        cipher.encrypt(zeroBlock) != cipher.encrypt(ffBlock));
}

void testRijndaelRepeatedKeys() {
    std::cout << "\n11. RIJNDAEL: REPEATED KEY SETTING\n";

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

    type key1(16, 0x01);
    type key2(16, 0x02);
    type block(16, 0x55);

    cipher.setKey(key1);
    type encrypted1 = cipher.encrypt(block);

    cipher.setKey(key2);
    type encrypted2 = cipher.encrypt(block);

    cipher.setKey(key1);
    type encryptedAgain = cipher.encrypt(block);

    check("Different keys produce different ciphertexts",
        encrypted1 != encrypted2);

    check("Returning to the first key restores the original result",
        encrypted1 == encryptedAgain);

    check("Decryption after changing key",
        cipher.decrypt(encryptedAgain) == block);
}

void testRijndaelInvalidInputs() {
    std::cout << "\n12. RIJNDAEL: INVALID INPUTS\n";

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

    checkThrows("Invalid block size in constructor", [&]() {
        Rijndael invalidCipher(64, 128, 0x1B, keyExpansion);
    });

    checkThrows("Invalid key size in constructor", [&]() {
        Rijndael invalidCipher(128, 64, 0x1B, keyExpansion);
    });

    checkThrows("Reducible modulus in constructor", [&]() {
        Rijndael invalidCipher(128, 128, 0x01, keyExpansion);
    });

    Rijndael cipher(128, 128, 0x1B, keyExpansion);
    cipherPtr = &cipher;

    checkThrows("Encryption without setting key", [&]() {
        cipher.encrypt(type(16, 0x00));
    });

    checkThrows("Decryption without setting key", [&]() {
        cipher.decrypt(type(16, 0x00));
    });

    checkThrows("Incorrect key size in setKey", [&]() {
        cipher.setKey(type(15, 0x00));
    });

    cipher.setKey(type(16, 0x00));

    checkThrows("Incorrect block size in encrypt", [&]() {
        cipher.encrypt(type(15, 0x00));
    });

    checkThrows("Incorrect block size in decrypt", [&]() {
        cipher.decrypt(type(17, 0x00));
    });
}

void testRijndaelCustomModulus() {
    std::cout << "\n13. RIJNDAEL: CUSTOM FIELD MODULUS\n";

    // 0x1D — другой неприводимый многочлен степени 8
    Rijndael* cipherPtr = nullptr;

    RijndaelKeyExpansion keyExpansion(
        128,
        128,
        0x1D,
        [&cipherPtr](const type& input) {
            if (cipherPtr == nullptr) throw Error::ERROR_INVALID_KEY;
            return cipherPtr->subBytes(input);
        }
    );

    Rijndael cipher(128, 128, 0x1D, keyExpansion);
    cipherPtr = &cipher;

    type key(16, 0x37);
    type block(16, 0xA5);

    cipher.setKey(key);

    check("Round-trip with custom irreducible modulus",
        cipher.decrypt(cipher.encrypt(block)) == block);
}

int main() {
    testAddition();
    testMultiplication();
    testInverse();
    testIrreducibility();
    testGenerateIrreduciblePolynomials();
    testFactorization();
    testExceptions();

    testRijndaelKnownVector();
    testRijndaelAllSizes();
    testRijndaelBoundaryBlocks();
    testRijndaelRepeatedKeys();
    testRijndaelInvalidInputs();
    testRijndaelCustomModulus();

    std::cout << "\n================================\n";
    std::cout << "PASSED: " << passed << '\n';
    std::cout << "FAILED: " << failed << '\n';
    std::cout << "TOTAL:  " << passed + failed << '\n';
    std::cout << "================================\n";

    return failed == 0 ? 0 : 1;
}
