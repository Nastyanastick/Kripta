
#include <iostream>
#include <vector>
#include <cstdint>
#include <bitset>
#include <string>

#include "laba1.h"
#include "CryptoContext.h"
#include "Feistel.h"
#include "Point5Demo.h"
#include "Point7Demo.h"

// ==================== ВРЕМЕННЫЙ ТЕСТОВЫЙ CIPHER ====================

class TestCipher : public ISymmetricCipher
{
public:
    void setKey(const type& key) override
    {
        // Для теста ключ не используется.
    }

    size_t getBlockSize() const override
    {
        return 4;
    }

    type encrypt(const type& block) override
    {
        type result = block;

        for (uint8_t& byte : result) {
            byte ^= 0xFF;
        }

        return result;
    }

    type decrypt(const type& block) override
    {
        // XOR с 0xFF обратим сам себе.
        return encrypt(block);
    }
};

// ==================== ТЕСТОВЫЕ РЕАЛИЗАЦИИ ДЛЯ POINT 3 ====================

class TestKeyExpansion : public IKeyExpansion
{
public:
    std::vector<type> generateRoundKeys(const type& key) override
    {
        return { key, key };
    }
};

class TestRoundTransform : public IRoundTransform
{
public:
    type transform(
        const type& inputBlock,
        const type& roundKey
    ) override
    {
        type result = inputBlock;

        for (size_t i = 0; i < result.size(); i++) {
            result[i] ^= roundKey[i];
        }

        return result;
    }
};

// ==================== ВЫВОД МАССИВА ====================

void printBytes(const type& data)
{
    for (uint8_t byte : data) {
        std::cout << std::bitset<8>(byte) << " ";
    }

    std::cout << "\n";
}

void printTestResult(const std::string& name, bool success)
{
    std::cout << name << ": "
              << (success ? "PASS" : "FAIL")
              << "\n";
}

// Проверка шифрования и восстановления данных для одного режима.
void testMode(
    const std::string& name,
    CryptoContext& context,
    const type& data,
    bool printDetails = true
)
{
    type encrypted = context.encrypt(data).get();
    type decrypted = context.decrypt(encrypted).get();

    bool success = (decrypted == data);

    printTestResult(name, success);

    if (printDetails) {
        std::cout << "Original size:  " << data.size() << " bytes\n";
        std::cout << "Encrypted size: " << encrypted.size() << " bytes\n";
        std::cout << "Decrypted size: " << decrypted.size() << " bytes\n";

        std::cout << "Original:  ";
        printBytes(data);

        std::cout << "Encrypted: ";
        printBytes(encrypted);

        std::cout << "Decrypted: ";
        printBytes(decrypted);
    }
}

// ==================== MAIN ====================

int main()
{
    size_t passed = 0;
    size_t failed = 0;

    auto recordResult = [&](bool success) {
        if (success) {
            ++passed;
        } else {
            ++failed;
        }
    };

    // ==================== POINT 1 ====================

    type value = { 0b10110010 };

    std::vector<size_t> pBlock0 = {
        7, 6, 5, 4, 3, 2, 1, 0
    };

    std::vector<size_t> pBlock1 = {
        8, 7, 6, 5, 4, 3, 2, 1
    };

    std::cout << "========== POINT 1 ==========\n";

    std::cout << "Input:   ";
    printBytes(value);

    std::cout << "MSB_0:   ";
    printBytes(permuteBits(value, pBlock0, BitIndexing::MSB_0));

    std::cout << "MSB_1:   ";
    printBytes(permuteBits(value, pBlock1, BitIndexing::MSB_1));

    std::cout << "LSB_0:   ";
    printBytes(permuteBits(value, pBlock0, BitIndexing::LSB_0));

    std::cout << "LSB_1:   ";
    printBytes(permuteBits(value, pBlock1, BitIndexing::LSB_1));

    // ==================== POINT 2.4 ====================

    std::cout << "\n========== POINT 2.4 ==========\n";

    TestCipher cipher;

    type key = { 1, 2, 3, 4 };
    type data = { 10, 20, 30, 40, 50, 60 };
    type iv = { 0, 0, 0, 0 };
    type randomDeltaIV = { 0, 0, 0, 1 };

    CryptoContext ecbContext(
        cipher, key, CipherMode::ECB, PaddingMode::PKCS7
    );

    CryptoContext cbcContext(
        cipher, key, CipherMode::CBC, PaddingMode::PKCS7, iv
    );

    CryptoContext pcbcContext(
        cipher, key, CipherMode::PCBC, PaddingMode::PKCS7, iv
    );

    CryptoContext cfbContext(
        cipher, key, CipherMode::CFB, PaddingMode::PKCS7, iv
    );

    CryptoContext ofbContext(
        cipher, key, CipherMode::OFB, PaddingMode::PKCS7, iv
    );

    CryptoContext ctrContext(
        cipher, key, CipherMode::CTR, PaddingMode::PKCS7, iv
    );

    CryptoContext randomDeltaContext(
        cipher, key, CipherMode::RANDOM_DELTA,
        PaddingMode::PKCS7, randomDeltaIV
    );

    std::cout << "\n--- Small data tests ---\n";

    auto runSmallTest = [&](const std::string& name, CryptoContext& context) {
        type encrypted = context.encrypt(data).get();
        type decrypted = context.decrypt(encrypted).get();

        bool success = (decrypted == data);
        printTestResult(name, success);
        recordResult(success);

        std::cout << "Original:  ";
        printBytes(data);

        std::cout << "Encrypted: ";
        printBytes(encrypted);

        std::cout << "Decrypted: ";
        printBytes(decrypted);
    };

    runSmallTest("ECB + PKCS7", ecbContext);
    runSmallTest("CBC + PKCS7", cbcContext);
    runSmallTest("PCBC + PKCS7", pcbcContext);
    runSmallTest("CFB + PKCS7", cfbContext);
    runSmallTest("OFB + PKCS7", ofbContext);
    runSmallTest("CTR + PKCS7", ctrContext);
    runSmallTest("Random Delta + PKCS7", randomDeltaContext);

    // ==================== БОЛЬШИЕ ДАННЫЕ ====================

    std::cout << "\n========== PARALLEL PROCESSING TESTS ==========\n";

    // 5000 блоков по 4 байта.
    // PKCS7 добавит ещё один блок: всего 5001.
    type largeData(4 * 5000, 0x42);

    auto runLargeTest = [&](const std::string& name, CryptoContext& context) {
        type encrypted = context.encrypt(largeData).get();
        type decrypted = context.decrypt(encrypted).get();

        bool success = (decrypted == largeData);
        printTestResult(name, success);
        recordResult(success);

        std::cout << "Original size:  " << largeData.size() << " bytes\n";
        std::cout << "Encrypted size: " << encrypted.size() << " bytes\n";
        std::cout << "Decrypted size: " << decrypted.size() << " bytes\n";
    };

    runLargeTest("ECB large data", ecbContext);
    runLargeTest("CBC large data", cbcContext);
    runLargeTest("CFB large data", cfbContext);
    runLargeTest("CTR large data", ctrContext);
    runLargeTest("Random Delta large data", randomDeltaContext);

    // ==================== POINT 3 ====================

    std::cout << "\n========== POINT 3 ==========\n";

    TestKeyExpansion keyExpansion;
    TestRoundTransform roundTransform;

    Feistel feistel(keyExpansion, roundTransform);

    type feistelKey = { 1, 2, 3, 4 };

    type feistelData = {
        10, 20, 30, 40,
        50, 60, 70, 80
    };

    feistel.setKey(feistelKey);

    type feistelEncrypted = feistel.encrypt(feistelData);
    type feistelDecrypted = feistel.decrypt(feistelEncrypted);

    std::cout << "Original:  ";
    printBytes(feistelData);

    std::cout << "Encrypted: ";
    printBytes(feistelEncrypted);

    std::cout << "Decrypted: ";
    printBytes(feistelDecrypted);

    bool feistelSuccess = (feistelDecrypted == feistelData);
    printTestResult("Feistel restored", feistelSuccess);
    recordResult(feistelSuccess);

    // ==================== SUMMARY ====================

    std::cout << "\n========== SUMMARY ==========\n";
    std::cout << "Passed: " << passed << "\n";
    std::cout << "Failed: " << failed << "\n";

    if (failed != 0) {
        std::cout << "Some tests FAILED.\n";
        return 1;
    }

    std::cout << "All registered tests PASSED.\n";

    // Демонстрации пунктов 5 и 7 запускаются отдельно,
    // потому что это демонстрационные функции, а не проверки выше.
    // runPoint5Demo();
    // runPoint7Demo();

    return 0;
}
