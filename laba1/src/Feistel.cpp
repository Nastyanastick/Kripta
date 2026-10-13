#include "Feistel.h"
#include <utility>

Feistel::Feistel(
    IKeyExpansion& keyExpansion,
    IRoundTransform& roundTransform
)
    : keyExpansion(keyExpansion),
    roundTransform(roundTransform)
{
}

void Feistel::setKey(const type& key)
{
    roundKeys = keyExpansion.generateRoundKeys(key);
}

size_t Feistel::getBlockSize() const
{
    return 8;
}

type Feistel::processBlock(
    const type& block,
    bool decrypt
)
{
    type L(block.begin(), block.begin() + block.size() / 2);
    type R(block.begin() + block.size() / 2, block.end());

    for (size_t i = 0; i < roundKeys.size(); i++) {
        size_t keyIndex;
        if (decrypt) {
            keyIndex = roundKeys.size() - 1 - i;
        }
        else {
            keyIndex = i;
        }
        type f = roundTransform.transform(R, roundKeys[keyIndex]);
        type oldL = L;
        L = R;
        for (size_t j = 0; j < R.size(); j++) { R[j] = oldL[j] ^ f[j]; }
    }

    if (decrypt) {
        std::swap(L, R);
    }

    type result = L;
    result.insert(result.end(), R.begin(), R.end());

    return result;
}

type Feistel::processBlock(
    const type& block,
    bool decrypt
)
{
    type L(block.begin(), block.begin() + block.size() / 2);
    type R(block.begin() + block.size() / 2, block.end());

    for (size_t i = 0; i < roundKeys.size(); i++) {
        size_t keyIndex;
        if (decrypt) {
            keyIndex = roundKeys.size() - 1 - i;
            type f = roundTransform.transform(L, roundKeys[keyIndex]);
            type oldL = L;
            for (size_t j = 0; j < L.size(); j++) {
                L[j] = R[j] ^ f[j];
            }
            R = oldL;
        }
        else {
            keyIndex = i;
            type f = roundTransform.transform(R, roundKeys[keyIndex]);
            type oldL = L;
            L = R;
            for (size_t j = 0; j < R.size(); j++) {
                R[j] = oldL[j] ^ f[j];
            }
        }
    }

    type result = L;
    result.insert(result.end(), R.begin(), R.end());

    return result;
}

type Feistel::encrypt(
    const type& block
)
{
    return processBlock(block, false);
}

type Feistel::decrypt(
    const type& block
)
{
    return processBlock(block, true);
}