#include "DEAL/DEAL.h"
#include "laba1.h"

#include <algorithm>

DEAL::DEAL()
    : feistel(keyExpansion, roundTransform)
{
}

void DEAL::setKey(const type& key)
{
    feistel.setKey(key);
}

size_t DEAL::getBlockSize() const
{
    return 16;
}

type DEAL::encrypt(const type& block)
{
    if (block.size() != getBlockSize()) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type swapped = block;

    std::swap_ranges(
        swapped.begin(),
        swapped.begin() + 8,
        swapped.begin() + 8
    );

    return feistel.encrypt(swapped);
}

type DEAL::decrypt(const type& block)
{
    if (block.size() != getBlockSize()) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type result = feistel.decrypt(block);

    std::swap_ranges(
        result.begin(),
        result.begin() + 8,
        result.begin() + 8
    );

    return result;
}