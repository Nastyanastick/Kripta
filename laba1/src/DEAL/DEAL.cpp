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

    return feistel.encrypt(swapped);
}

type DEAL::decrypt(const type& block)
{
    if (block.size() != getBlockSize()) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type result = feistel.decrypt(block);

    return result;
}