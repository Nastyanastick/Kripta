#include <iostream>
#include <vector>
#include <cstdint>
#include <bitset>

#include "laba1.h"
#include "CryptoContext.h"
#include "Feistel.h"
#include "Point5Demo.h"

// ==================== ВРЕМЕННЫЙ ТЕСТОВЫЙ CIPHER ====================

class TestCipher : public ISymmetricCipher
{
public:
    void setKey(const type& key) override
    {
        // Для теста ключ не используется
    }

    size_t getBlockSize() const override
    {
        return 4;
    }

    type encrypt(
        const type& block
    ) override
    {
        type result = block;

        for (uint8_t& byte : result) {
            byte ^= 0xFF;
        }

        return result;
    }

    type decrypt(
        const type& block
    ) override
    {
        // XOR с 0xFF обратим сам себе
        return encrypt(block);
    }
};

// ==================== ТЕСТОВЫЕ РЕАЛИЗАЦИИ ДЛЯ POINT 3 ====================

class TestKeyExpansion : public IKeyExpansion
{
public:
    std::vector<type> generateRoundKeys(
        const type& key
    ) override
    {
        return {
            key,
            key
        };
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


int main()
{
    // ==================== ПУНКТ 1 ====================

    type value = {0b10110010};

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
    printBytes(
        permuteBits(value, pBlock0, BitIndexing::MSB_0)
    );

    std::cout << "MSB_1:   ";
    printBytes(
        permuteBits(value, pBlock1, BitIndexing::MSB_1)
    );

    std::cout << "LSB_0:   ";
    printBytes(
        permuteBits(value, pBlock0, BitIndexing::LSB_0)
    );

    std::cout << "LSB_1:   ";
    printBytes(
        permuteBits(value, pBlock1, BitIndexing::LSB_1)
    );


    // ==================== ПУНКТ 2.4 ====================

    std::cout << "\n========== POINT 2.4 ==========\n";

    TestCipher cipher;

    type key = {
        1, 2, 3, 4
    };

    type data = {
        10, 20, 30, 40, 50, 60
    };

    type iv = {
        0, 0, 0, 0
    };


    // ---------- ECB + PKCS7 ----------

    std::cout << "\nECB + PKCS7\n";

    CryptoContext ecbContext(
        cipher,
        key,
        CipherMode::ECB,
        PaddingMode::PKCS7
    );

    type encryptedECB =
        ecbContext.encrypt(data).get();

    type decryptedECB =
        ecbContext.decrypt(encryptedECB).get();

    std::cout << "Original:  ";
    printBytes(data);

    std::cout << "Encrypted: ";
    printBytes(encryptedECB);

    std::cout << "Decrypted: ";
    printBytes(decryptedECB);


    // ---------- CBC + PKCS7 ----------

    std::cout << "\nCBC + PKCS7\n";

    CryptoContext cbcContext(
        cipher,
        key,
        CipherMode::CBC,
        PaddingMode::PKCS7,
        iv
    );

    type encryptedCBC =
        cbcContext.encrypt(data).get();

    type decryptedCBC =
        cbcContext.decrypt(encryptedCBC).get();

    std::cout << "Original:  ";
    printBytes(data);

    std::cout << "Encrypted: ";
    printBytes(encryptedCBC);

    std::cout << "Decrypted: ";
    printBytes(decryptedCBC);
    

    // ---------- PCBC + PKCS7 ----------

    std::cout << "\nPCBC + PKCS7\n";

    CryptoContext pcbcContext(
        cipher,
        key,
        CipherMode::PCBC,
        PaddingMode::PKCS7,
        iv
    );

    type encryptedPCBC =
        pcbcContext.encrypt(data).get();

    type decryptedPCBC =
        pcbcContext.decrypt(encryptedPCBC).get();

    std::cout << "Original:  ";
    printBytes(data);

    std::cout << "Encrypted: ";
    printBytes(encryptedPCBC);

    std::cout << "Decrypted: ";
    printBytes(decryptedPCBC);


    // ---------- CFB + PKCS7 ----------

    std::cout << "\nCFB + PKCS7\n";

    CryptoContext cfbContext(
        cipher,
        key,
        CipherMode::CFB,
        PaddingMode::PKCS7,
        iv
    );

    type encryptedCFB =
        cfbContext.encrypt(data).get();

    type decryptedCFB =
        cfbContext.decrypt(encryptedCFB).get();

    std::cout << "Original:  ";
    printBytes(data);

    std::cout << "Encrypted: ";
    printBytes(encryptedCFB);

    std::cout << "Decrypted: ";
    printBytes(decryptedCFB);


    // ---------- OFB + PKCS7 ----------

    std::cout << "\nOFB + PKCS7\n";

    CryptoContext ofbContext(
        cipher,
        key,
        CipherMode::OFB,
        PaddingMode::PKCS7,
        iv
    );

    type encryptedOFB =
        ofbContext.encrypt(data).get();

    type decryptedOFB =
        ofbContext.decrypt(encryptedOFB).get();

    std::cout << "Original:  ";
    printBytes(data);

    std::cout << "Encrypted: ";
    printBytes(encryptedOFB);

    std::cout << "Decrypted: ";
    printBytes(decryptedOFB);


    // ---------- CTR + PKCS7 ----------

    std::cout << "\nCTR + PKCS7\n";

    CryptoContext ctrContext(
        cipher,
        key,
        CipherMode::CTR,
        PaddingMode::PKCS7,
        iv
    );

    type encryptedCTR =
        ctrContext.encrypt(data).get();

    type decryptedCTR =
        ctrContext.decrypt(encryptedCTR).get();

    std::cout << "Original:  ";
    printBytes(data);

    std::cout << "Encrypted: ";
    printBytes(encryptedCTR);

    std::cout << "Decrypted: ";
    printBytes(decryptedCTR);

    type randomDeltaIV = {0, 0, 0, 1};

    CryptoContext randomDeltaContext(
        cipher,
        key,
        CipherMode::RANDOM_DELTA,
        PaddingMode::PKCS7,
        randomDeltaIV
    );

    auto randomDeltaEncrypted = randomDeltaContext.encrypt(data).get();
    auto randomDeltaDecrypted = randomDeltaContext.decrypt(randomDeltaEncrypted).get();

    std::cout << "Random Delta encrypted: ";
    for (uint8_t byte : randomDeltaEncrypted) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << "\n";

    std::cout << "Random Delta decrypted: ";
    for (uint8_t byte : randomDeltaDecrypted) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << "\n";

    std::cout << "Random Delta restored: "
            << (randomDeltaDecrypted == data ? "YES" : "NO")
            << "\n";

    // ==================== ПУНКТ 3 ====================

    std::cout << "\n========== POINT 3 ==========\n";

    TestKeyExpansion keyExpansion;
    TestRoundTransform roundTransform;

    Feistel feistel(
        keyExpansion,
        roundTransform
    );

    type feistelKey = {
        1, 2, 3, 4
    };

    type feistelData = {
        10, 20, 30, 40,
        50, 60, 70, 80
    };

    feistel.setKey(feistelKey);

    type feistelEncrypted =
        feistel.encrypt(feistelData);

    type feistelDecrypted =
        feistel.decrypt(feistelEncrypted);

    std::cout << "Original:  ";
    printBytes(feistelData);

    std::cout << "Encrypted: ";
    printBytes(feistelEncrypted);

    std::cout << "Decrypted: ";
    printBytes(feistelDecrypted);

    runPoint5Demo();


    return 0;
}