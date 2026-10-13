#pragma once
#include <vector>
#include <cstdint>

using type = std::vector<uint8_t>;

class ISymmetricCipher {
public:
    virtual void setKey(
        const type& key
    ) = 0;

    virtual size_t getBlockSize() const = 0;

    virtual type encrypt(
        const type& block
    ) = 0;

    virtual type decrypt(
        const type& block
    ) = 0;

    virtual ~ISymmetricCipher() = default;
};