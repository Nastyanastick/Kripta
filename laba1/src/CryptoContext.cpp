#include <vector>
#include <cstdint>
#include <random>
#include <algorithm>
#include <fstream>
#include "include/CryptoContext.h"
#include "laba1.h"
#include <iostream>

std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<int> dist(0, 255);

type CryptoContext::xorBlocks(
    const type& a,
    const type& b
)
{
    if (a.size() != b.size()) { throw Error::ERROR_BLOCK_SIZE; }
    type result(a.size());
    for (size_t i = 0; i < a.size(); i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

type addVectors(
    const type& a,
    const type& b)
{
    if (a.size() != b.size()) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type result(a.size());
    uint16_t carry = 0;

    for (int i = static_cast<int>(a.size()) - 1; i >= 0; i--) {
        uint16_t sum = static_cast<uint16_t>(a[i])
                    + static_cast<uint16_t>(b[i])
                    + carry;

        result[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = sum >> 8;
    }
    return result;
}

type multiplyVector(
    const type& value,
    size_t multiplier)
{
    type result(value.size(), 0);
    type current = value;

    while (multiplier > 0) {
        if (multiplier & 1) {
            result = addVectors(result, current);
        }

        multiplier >>= 1;

        if (multiplier > 0) {
            current = addVectors(current, current);
        }
    }
    return result;
}

CryptoContext::CryptoContext(
    ISymmetricCipher& cipher,
    const type& key,
    CipherMode cipherMode,
    PaddingMode paddingMode,
    const type& iv,
    const std::vector<std::string>& additionalParams
)
    : cipher(cipher),
      key(key),
      cipherMode(cipherMode),
      paddingMode(paddingMode),
      iv(iv),
      additionalParams(additionalParams)
{
    cipher.setKey(key);
}

type CryptoContext::addPadding(
    const type& data
)
{
    size_t blockSize = cipher.getBlockSize();
    size_t paddingSize = blockSize - data.size() % blockSize;

    type result = data;

    if (paddingMode == PaddingMode::Zeros) {
        if (data.size() % blockSize == 0) { paddingSize = 0; }
        for (size_t i = 0; i < paddingSize; i++) {
            result.push_back(0);
        }
    }

    else if (paddingMode == PaddingMode::ANSI_X923) {
        for (size_t i = 0; i < paddingSize - 1; i++) {
            result.push_back(0);
        }
        result.push_back(static_cast<uint8_t>(paddingSize));
    }

    else if (paddingMode == PaddingMode::PKCS7) {
        for (size_t i = 0; i < paddingSize; i++) {
            result.push_back(static_cast<uint8_t>(paddingSize));
        }
    }

    else if (paddingMode == PaddingMode::ISO10126) {
        for (size_t i = 0; i < paddingSize - 1; i++) {
            result.push_back(static_cast<uint8_t>(dist(gen)));
        }
        result.push_back(static_cast<uint8_t>(paddingSize));
    }

    return result;
}

type CryptoContext::removePadding(
    const type& data
)
{
    type result = data;

    if (paddingMode == PaddingMode::Zeros) {
        while (!result.empty() && result.back() == 0) {
            result.pop_back();
        }
    }

    else if (paddingMode == PaddingMode::ANSI_X923) {
        if (result.empty()) {
            throw Error::ERROR_BLOCK_SIZE;
        }

        size_t paddingSize = result.back();

        if (paddingSize == 0 || paddingSize > result.size()) {
            throw Error::ERROR_BLOCK_SIZE;
        }

        for (size_t i = 0; i < paddingSize - 1; i++) {
            if (result[result.size() - 2 - i] != 0) {   // все байты перед последним нули, последний без проверки
                throw Error::ERROR_BLOCK_SIZE;
            }
        }

        for (size_t i = 0; i < paddingSize; i++) {
            result.pop_back();
        }
    }

    else if (paddingMode == PaddingMode::PKCS7) {
        if (result.empty()) {
            throw Error::ERROR_BLOCK_SIZE;
        }

        size_t paddingSize = result.back();

        if (paddingSize == 0 || paddingSize > result.size()) {
            throw Error::ERROR_BLOCK_SIZE;
        }

        for (size_t i = 0; i < paddingSize; i++) {
            if (result[result.size() - 1 - i] != paddingSize) {
                throw Error::ERROR_BLOCK_SIZE;
            }
        }

        for (size_t i = 0; i < paddingSize; i++) {
            result.pop_back();
        }
    }

    else if (paddingMode == PaddingMode::ISO10126) {
        if (result.empty()) {
            throw Error::ERROR_BLOCK_SIZE;
        }

        size_t paddingSize = result.back();

        if (paddingSize == 0 || paddingSize > result.size()) {
            throw Error::ERROR_BLOCK_SIZE;
        }

        for (size_t i = 0; i < paddingSize; i++) {
            result.pop_back();
        }
    }
    return result;
}

type CryptoContext::encryptECB(
    const type& data
)
{
    type paddedData = addPadding(data);
    type result;

    size_t blockSize = cipher.getBlockSize();

    std::vector<std::future<type>> futures;

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {
        type block(
            paddedData.begin() + i,
            paddedData.begin() + i + blockSize
        );

        futures.push_back(
            std::async(
                std::launch::async,
                [this, block]() {
                    return cipher.encrypt(block);
                }
            )
        );
    }

    for (auto& future : futures) {
        type encryptedBlock = future.get();
        result.insert(
            result.end(),
            encryptedBlock.begin(),
            encryptedBlock.end()
        );
    }

    return result;
}

type CryptoContext::decryptECB(
    const type& data
)
{
    type result;
    size_t blockSize = cipher.getBlockSize();

    std::vector<std::future<type>> futures;

    for (size_t i = 0; i < data.size(); i += blockSize) {
        type block(
            data.begin() + i,
            data.begin() + i + blockSize
        );

        futures.push_back(
            std::async(
                std::launch::async,
                [this, block]() {
                    return cipher.decrypt(block);
                }
            )
        );
    }

    for (auto& future : futures) {
        type decryptedBlock = future.get();
        result.insert(
            result.end(),
            decryptedBlock.begin(),
            decryptedBlock.end()
        );
    }
    return removePadding(result);
}

type CryptoContext::encryptCBC(
    const type& data
)
{
    type paddedData = addPadding(data);
    type result;

    size_t blockSize = cipher.getBlockSize();
    type previousBlock = iv;

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {
        type block(
            paddedData.begin() + i,
            paddedData.begin() + i + blockSize
        );

        block = xorBlocks(block, previousBlock);

        type encryptedBlock = cipher.encrypt(block);

        result.insert(
            result.end(),
            encryptedBlock.begin(),
            encryptedBlock.end()
        );

        previousBlock = encryptedBlock;
    }
    return result;
}

type CryptoContext::decryptCBC(
    const type& data
)
{
    type result;

    size_t blockSize = cipher.getBlockSize();
    type previousBlock = iv;

    for (size_t i = 0; i < data.size(); i += blockSize) {
        type block(
            data.begin() + i,
            data.begin() + i + blockSize
        );

        type decryptedBlock = cipher.decrypt(block);

        decryptedBlock = xorBlocks(decryptedBlock, previousBlock);

        result.insert(
            result.end(),
            decryptedBlock.begin(),
            decryptedBlock.end()
        );

        previousBlock = block;
    }
    return removePadding(result);
}

type CryptoContext::encryptPCBC(
    const type& data
)
{
    type paddedData = addPadding(data);
    type result;

    size_t blockSize = cipher.getBlockSize();

    type previousPlainBlock = iv;
    type previousCipherBlock = iv;

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {
        type block(
            paddedData.begin() + i,
            paddedData.begin() + i + blockSize
        );

        type xoredBlock =
            xorBlocks(block, previousPlainBlock);

        xoredBlock =
            xorBlocks(xoredBlock, previousCipherBlock);

        type encryptedBlock =
            cipher.encrypt(xoredBlock);

        result.insert(
            result.end(),
            encryptedBlock.begin(),
            encryptedBlock.end()
        );

        previousPlainBlock = block;
        previousCipherBlock = encryptedBlock;
    }
    return result;
}

type CryptoContext::decryptPCBC(
    const type& data
)
{
    type result;

    size_t blockSize = cipher.getBlockSize();

    type previousPlainBlock = iv;
    type previousCipherBlock = iv;

    for (size_t i = 0; i < data.size(); i += blockSize) {
        type block(
            data.begin() + i,
            data.begin() + i + blockSize
        );

        type decryptedBlock =
            cipher.decrypt(block);

        decryptedBlock =
            xorBlocks(decryptedBlock, previousPlainBlock);

        decryptedBlock =
            xorBlocks(decryptedBlock, previousCipherBlock);

        result.insert(
            result.end(),
            decryptedBlock.begin(),
            decryptedBlock.end()
        );

        previousPlainBlock = decryptedBlock;
        previousCipherBlock = block;
    }
    return removePadding(result);
}

type CryptoContext::encryptCFB(
    const type& data
)
{
    type paddedData = addPadding(data);
    type result;

    size_t blockSize = cipher.getBlockSize();
    type previousBlock = iv;

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {
        type block(
            paddedData.begin() + i,
            paddedData.begin() + i + blockSize
        );

        type encryptedPreviousBlock =
            cipher.encrypt(previousBlock);

        type encryptedBlock =
            xorBlocks(block, encryptedPreviousBlock);

        result.insert(
            result.end(),
            encryptedBlock.begin(),
            encryptedBlock.end()
        );

        previousBlock = encryptedBlock;
    }
    return result;
}

type CryptoContext::decryptCFB(
    const type& data
)
{
    type result;

    size_t blockSize = cipher.getBlockSize();
    type previousBlock = iv;

    for (size_t i = 0; i < data.size(); i += blockSize) {
        type block(
            data.begin() + i,
            data.begin() + i + blockSize
        );

        type encryptedPreviousBlock =
            cipher.encrypt(previousBlock);

        type decryptedBlock =
            xorBlocks(block, encryptedPreviousBlock);

        result.insert(
            result.end(),
            decryptedBlock.begin(),
            decryptedBlock.end()
        );

        previousBlock = block;
    }
    return removePadding(result);
}

type CryptoContext::encryptOFB(
    const type& data
)
{
    type paddedData = addPadding(data);
    type result;

    size_t blockSize = cipher.getBlockSize();
    type previousBlock = iv;

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {
        type block(
            paddedData.begin() + i,
            paddedData.begin() + i + blockSize
        );

        previousBlock = cipher.encrypt(previousBlock);

        type encryptedBlock =
            xorBlocks(block, previousBlock);

        result.insert(
            result.end(),
            encryptedBlock.begin(),
            encryptedBlock.end()
        );
    }
    return result;
}

type CryptoContext::decryptOFB(
    const type& data
)
{
    type result;

    size_t blockSize = cipher.getBlockSize();
    type previousBlock = iv;

    for (size_t i = 0; i < data.size(); i += blockSize) {
        type block(
            data.begin() + i,
            data.begin() + i + blockSize
        );

        previousBlock = cipher.encrypt(previousBlock);

        type decryptedBlock =
            xorBlocks(block, previousBlock);

        result.insert(
            result.end(),
            decryptedBlock.begin(),
            decryptedBlock.end()
        );
    }
    return removePadding(result);
}

type CryptoContext::encryptCTR(
    const type& data
)
{
    type paddedData = addPadding(data);
    type result;

    size_t blockSize = cipher.getBlockSize();
    type counter = iv;

    std::vector<std::future<type>> futures;

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {
        type currentCounter = counter;
        futures.push_back(
            std::async(
                std::launch::async,
                [this, currentCounter]() {
                    return cipher.encrypt(currentCounter);
                }
            )
        );

        for (int j = counter.size() - 1; j >= 0; j--) {
            counter[j]++;
            if (counter[j] != 0) {
                break;
            }
        }
    }

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {
        type block (
            paddedData.begin() + i,
            paddedData.begin() + i + blockSize
        );
        type gamma = futures[i / blockSize].get();
        type encryptBlock = xorBlocks(block, gamma);
        result.insert(
            result.end(),
            encryptBlock.begin(),
            encryptBlock.end()
        );
    }
    return result;
}

type CryptoContext::decryptCTR(
    const type& data
)
{
    type result;

    size_t blockSize = cipher.getBlockSize();
    type counter = iv;

    std::vector<std::future<type>> futures;

    for (size_t i = 0; i < data.size(); i += blockSize) {

        type currentCounter = counter;

        futures.push_back(
            std::async(
                std::launch::async,
                [this, currentCounter]() {
                    return cipher.encrypt(currentCounter);
                }
            )
        );

        for (int j = counter.size() - 1; j >= 0; j--) {
            counter[j]++;
            if (counter[j] != 0) {
                break;
            }
        }
    }

    for (size_t i = 0; i < data.size(); i += blockSize) {
        type block(
            data.begin() + i,
            data.begin() + i + blockSize
        );

        type gamma = futures[i / blockSize].get();
        type decryptedBlock = xorBlocks(block, gamma);
        result.insert(
            result.end(),
            decryptedBlock.begin(),
            decryptedBlock.end()
        );
    }

    return removePadding(result);
}

type CryptoContext::encryptRandomDelta(
    const type& data)
{
    size_t blockSize = cipher.getBlockSize();

    if (blockSize % 2 != 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    if (iv.size() != blockSize) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type paddedData = addPadding(data);

    size_t halfSize = blockSize / 2; // размер половины блока

    type counterIV(
        iv.begin(),
        iv.begin() + halfSize
    );

    type delta(
        iv.begin() + halfSize,
        iv.end()
    );

    if (delta.back() % 2 == 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type result;
    std::vector<std::future<type>> futures;

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {
        type countI = addVectors(counterIV, multiplyVector(delta, i / blockSize));

        type tag = countI;
        tag.insert(tag.end(), delta.begin(), delta.end());

        futures.push_back(
            std::async(
                std::launch::async,
                [this, tag]() {
                    return cipher.encrypt(tag);
                }
            )
        );
    }

    for (size_t i = 0; i < paddedData.size(); i += blockSize) {

        type block(
            paddedData.begin() + i,
            paddedData.begin() + i + blockSize
        );

        type gamma = futures[i / blockSize].get();

        type encryptedBlock = xorBlocks(block, gamma);

        result.insert(
            result.end(),
            encryptedBlock.begin(),
            encryptedBlock.end()
        );
    }

    return result;
}

type CryptoContext::decryptRandomDelta(
    const type& data)
{
    size_t blockSize = cipher.getBlockSize();

    if (blockSize % 2 != 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    if (iv.size() != blockSize) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    if (data.size() % blockSize != 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    size_t halfSize = blockSize / 2;

    type counterIV(
        iv.begin(),
        iv.begin() + halfSize
    );

    type delta(
        iv.begin() + halfSize,
        iv.end()
    );

    if (delta.back() % 2 == 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type result;
    std::vector<std::future<type>> futures;

    for (size_t i = 0; i < data.size(); i += blockSize) {

        size_t blockIndex = i / blockSize;
        type countI =
            addVectors(counterIV, multiplyVector(delta, blockIndex));

        type tag = countI;
        tag.insert(tag.end(), delta.begin(), delta.end());

        futures.push_back(
            std::async(
                std::launch::async,
                [this, tag]() {
                    return cipher.encrypt(tag);
                }
            )
        );
    }

    for (size_t i = 0; i < data.size(); i += blockSize) {

        size_t blockIndex = i / blockSize;

        type block(
            data.begin() + i,
            data.begin() + i + blockSize
        );

        type gamma = futures[blockIndex].get();

        type decryptedBlock =
            xorBlocks(block, gamma);

        result.insert(
            result.end(),
            decryptedBlock.begin(),
            decryptedBlock.end()
        );
    }

    return removePadding(result);
}

std::future<type> CryptoContext::encrypt(
    const type& data
)
{
    return std::async(
        std::launch::async,
        [this, data]() {
            switch (cipherMode) {
                case CipherMode::ECB:
                    return encryptECB(data);

                case CipherMode::CBC:
                    return encryptCBC(data);

                case CipherMode::PCBC:
                    return encryptPCBC(data);

                case CipherMode::CFB:
                    return encryptCFB(data);

                case CipherMode::OFB:
                    return encryptOFB(data);

                case CipherMode::CTR:
                    return encryptCTR(data);

                case CipherMode::RANDOM_DELTA:
                    return encryptRandomDelta(data);
            }

            throw Error::ERROR_BLOCK_SIZE;
        }
    );
}

std::future<type> CryptoContext::decrypt(
    const type& data
)
{
    return std::async(
        std::launch::async,
        [this, data]() {
            switch (cipherMode) {
                case CipherMode::ECB:
                    return decryptECB(data);

                case CipherMode::CBC:
                    return decryptCBC(data);

                case CipherMode::PCBC:
                    return decryptPCBC(data);

                case CipherMode::CFB:
                    return decryptCFB(data);

                case CipherMode::OFB:
                    return decryptOFB(data);

                case CipherMode::CTR:
                    return decryptCTR(data);

                case CipherMode::RANDOM_DELTA:
                    return decryptRandomDelta(data);
            }

            throw Error::ERROR_BLOCK_SIZE;
        }
    );
}

std::future<void> CryptoContext::encrypt(
    const std::string& inputPath,
    const std::string& outputPath
)
{
    return std::async(
        std::launch::async,
        [this, inputPath, outputPath]() {
            std::ifstream inputFile(
                inputPath,
                std::ios::binary
            );

            if (!inputFile) {
                throw Error::ERROR_BLOCK_SIZE;
            }

            type data(
                (std::istreambuf_iterator<char>(inputFile)),
                std::istreambuf_iterator<char>()
            );

            inputFile.close();

            type encryptedData = encrypt(data).get();

            std::ofstream outputFile(
                outputPath,
                std::ios::binary
            );

            if (!outputFile) {
                throw Error::ERROR_BLOCK_SIZE;
            }

            outputFile.write(
                reinterpret_cast<const char*>(encryptedData.data()),
                encryptedData.size()
            );

            outputFile.close();
        }
    );
}


std::future<void> CryptoContext::decrypt(
    const std::string& inputPath,
    const std::string& outputPath
)
{
    return std::async(
        std::launch::async,
        [this, inputPath, outputPath]() {
            std::ifstream inputFile(
                inputPath,
                std::ios::binary
            );

            if (!inputFile) {
                throw Error::ERROR_BLOCK_SIZE;
            }

            type data(
                (std::istreambuf_iterator<char>(inputFile)),
                std::istreambuf_iterator<char>()
            );

            inputFile.close();

            type decryptedData = decrypt(data).get();

            std::ofstream outputFile(
                outputPath,
                std::ios::binary
            );

            if (!outputFile) {
                throw Error::ERROR_BLOCK_SIZE;
            }

            outputFile.write(
                reinterpret_cast<const char*>(decryptedData.data()),
                decryptedData.size()
            );

            outputFile.close();
        }
    );
}