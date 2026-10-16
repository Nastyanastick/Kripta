#include <vector>
#include <cstdint>
#include <random>
#include <algorithm>
#include <fstream>
#include <thread>
#include "include/CryptoContext.h"
#include "laba1.h"
#include <iostream>
#include <future>

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
// ограниченное число задач на одну группу блоков. группы обрабатываются параллельно
template <typename Transform>
type processParallelBlocks(
    const type& data,
    size_t blockSize,
    Transform transform
)
{
    if (blockSize == 0 || data.size() % blockSize != 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    const size_t totalBlocks = data.size() / blockSize;

    type result;
    result.reserve(data.size());

    constexpr size_t blocksPerTask = 4096;

    // небольшие данные обрабатываем без дополнительных задач.
    if (totalBlocks <= blocksPerTask) {
        for (size_t i = 0; i < totalBlocks; ++i) {
            type block(
                data.begin() + i * blockSize,
                data.begin() + (i + 1) * blockSize
            );

            type transformed = transform(block, i);

            result.insert(
                result.end(),
                transformed.begin(),
                transformed.end()
            );
        }

        return result;
    }

    // ограничиваем число одновременно работающих задач.
    const size_t hardwareThreads = std::thread::hardware_concurrency();

    const size_t workers = hardwareThreads == 0
        ? 2
        : std::min<size_t>(hardwareThreads, 4);

    for (size_t batchStart = 0; batchStart < totalBlocks; batchStart += workers * blocksPerTask) {
        std::vector<std::future<type>> futures;

        const size_t batchEnd = std::min(totalBlocks, batchStart + workers * blocksPerTask);

        for (size_t start = batchStart; start < batchEnd; start += blocksPerTask) {
            const size_t end = std::min(batchEnd, start + blocksPerTask);

            futures.push_back(std::async(
                std::launch::async,
                [&data, blockSize, transform, start, end]() {
                    type part;
                    part.reserve((end - start) * blockSize);

                    for (size_t i = start; i < end; ++i) {
                        type block(
                            data.begin() + i * blockSize,
                            data.begin() + (i + 1) * blockSize
                        );

                        type transformed = transform(block, i);

                        part.insert(
                            part.end(),
                            transformed.begin(),
                            transformed.end()
                        );
                    }

                    return part;
                }
            ));
        }

        for (auto& future : futures) {
            type part = future.get();

            result.insert(
                result.end(),
                part.begin(),
                part.end()
            );
        }
    }

    return result;
}

type makeCounter(const type& iv, size_t blockIndex)
{
    type counter = iv;
    size_t carry = blockIndex; // на сколько увеличиваем счетчик

    for (int j = static_cast<int>(counter.size()) - 1; j >= 0 && carry > 0; --j) {
        size_t sum = counter[j] + (carry & 0xFF);
        counter[j] = static_cast<uint8_t>(sum & 0xFF); // оставляем млашие 8 бит
        carry = (carry >> 8) + (sum >> 8);
    }

    if (carry != 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    return counter;
}

type CryptoContext::encryptECB(const type& data)
{
    type paddedData = addPadding(data);
    size_t blockSize = cipher.getBlockSize();

    return processParallelBlocks(
        paddedData,
        blockSize,
        [this](const type& block, size_t) {
            return cipher.encrypt(block);
        }
    );
}

type CryptoContext::decryptECB(const type& data)
{
    size_t blockSize = cipher.getBlockSize();

    type result = processParallelBlocks(
        data,
        blockSize,
        [this](const type& block, size_t) {
            return cipher.decrypt(block);
        }
    );

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
    size_t blockSize = cipher.getBlockSize();

    if (blockSize == 0 || data.size() % blockSize != 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type result = processParallelBlocks(
        data,
        blockSize,
        [this, &data, blockSize](const type& block, size_t index) {
            type decryptedBlock = cipher.decrypt(block);
            type previousBlock;

            if (index == 0) {
                previousBlock = iv;
            }
            else {
                size_t previousOffset = (index - 1) * blockSize; // начало предыдущего блока в массиве

                previousBlock = type(data.begin() + previousOffset, data.begin() + previousOffset + blockSize);
            }

            return xorBlocks(decryptedBlock, previousBlock);
        }
    );

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
    size_t blockSize = cipher.getBlockSize();

    if (blockSize == 0 || data.size() % blockSize != 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type result = processParallelBlocks(
        data,
        blockSize,
        [this, &data, blockSize](const type& block, size_t index) {
            type previousBlock;

            if (index == 0) {
                previousBlock = iv;
            }
            else {
                size_t previousOffset = (index - 1) * blockSize;

                previousBlock = type(data.begin() + previousOffset, data.begin() + previousOffset + blockSize);
            }

            type encryptedPreviousBlock = cipher.encrypt(previousBlock);

            return xorBlocks(block, encryptedPreviousBlock);
        }
    );

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

type CryptoContext::encryptCTR(const type& data)
{
    type paddedData = addPadding(data);
    size_t blockSize = cipher.getBlockSize();

    return processParallelBlocks(
        paddedData,
        blockSize,
        [this](const type& block, size_t index) {
            type counter = makeCounter(iv, index);
            type gamma = cipher.encrypt(counter);
            return xorBlocks(block, gamma);
        }
    );
}

type CryptoContext::decryptCTR(const type& data)
{
    size_t blockSize = cipher.getBlockSize();

    type result = processParallelBlocks(
        data,
        blockSize,
        [this](const type& block, size_t index) {
            type counter = makeCounter(iv, index);
            type gamma = cipher.encrypt(counter);
            return xorBlocks(block, gamma);
        }
    );

    return removePadding(result);
}

type CryptoContext::encryptRandomDelta(const type& data)
{
    size_t blockSize = cipher.getBlockSize();

    if (blockSize % 2 != 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    if (iv.size() != blockSize) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type paddedData = addPadding(data);

    size_t halfSize = blockSize / 2;

    type counterIV(iv.begin(), iv.begin() + halfSize);

    type delta(iv.begin() + halfSize, iv.end());

    if (delta.back() % 2 == 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    return processParallelBlocks(
        paddedData,
        blockSize,
        [this, counterIV, delta](const type& block, size_t index) {
            type countI = addVectors(counterIV, multiplyVector(delta, index));

            type tag = countI;
            tag.insert(tag.end(), delta.begin(), delta.end());

            type gamma = cipher.encrypt(tag);

            return xorBlocks(block, gamma);
        }
    );
}

type CryptoContext::decryptRandomDelta(const type& data)
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

    type counterIV(iv.begin(), iv.begin() + halfSize);

    type delta(iv.begin() + halfSize, iv.end());

    if (delta.back() % 2 == 0) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type result = processParallelBlocks(
        data,
        blockSize,
        [this, counterIV, delta](const type& block, size_t index) {
            type countI = addVectors(counterIV, multiplyVector(delta, index));

            type tag = countI;
            tag.insert(tag.end(), delta.begin(), delta.end());

            type gamma = cipher.encrypt(tag);

            return xorBlocks(block, gamma);
        }
    );

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
            size_t blockSize = cipher.getBlockSize();
            if (blockSize == 0 || data.size() % blockSize != 0) {
                throw Error::ERROR_BLOCK_SIZE;
            }
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