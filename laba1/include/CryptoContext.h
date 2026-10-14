#pragma once

#include <vector>
#include <cstdint>
#include <future>
#include <string>
#include "ISymmetricCipher.h"

using type = std::vector<uint8_t>;

enum struct CipherMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RANDOM_DELTA
};

enum struct PaddingMode {
    Zeros,
    ANSI_X923,
    PKCS7,
    ISO10126
};

class CryptoContext {
private:
    ISymmetricCipher& cipher;
    type key;
    CipherMode cipherMode;
    PaddingMode paddingMode;
    type iv;
    std::vector<std::string> additionalParams;

    type xorBlocks(
        const type& a,
        const type& b
    );

    type addPadding(
        const type& data
    );

    type removePadding(
        const type& data
    );

    type encryptECB(
        const type& data
    );

    type decryptECB(
        const type& data
    );

    type encryptCBC(
        const type& data
    );

    type decryptCBC(
        const type& data
    );

    type encryptPCBC(
        const type& data
    );

    type decryptPCBC(
        const type& data
    );

    type encryptCFB(
        const type& data
    );

    type decryptCFB(
        const type& data
    );

    type encryptOFB(
        const type& data
    );

    type decryptOFB(
        const type& data
    );

    type encryptCTR(
        const type& data
    );

    type decryptCTR(
        const type& data
    );

    type encryptRandomDelta(
        const type& data
    );

    type decryptRandomDelta(
        const type& data
    );

public:
    CryptoContext(
        ISymmetricCipher& cipher,
        const type& key,
        CipherMode cipherMode,
        PaddingMode paddingMode,
        const type& iv = {},
        const std::vector<std::string>& additionalParams = {}
    );

    std::future<type> encrypt(
        const type& data
    );

    std::future<type> decrypt(
        const type& data
    );

    std::future<void> encrypt(
        const std::string& inputPath,
        const std::string& outputPath
    );

    std::future<void> decrypt(
        const std::string& inputPath,
        const std::string& outputPath
    );
};