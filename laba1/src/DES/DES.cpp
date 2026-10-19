#include <algorithm>
#include "DES/DES.h"
#include "DES/DESConstants.h"
#include "laba1.h"

DES::DES()
    : feistel(keyExpansion, roundTransform)
{
}

void DES::setKey(const type& key)
{
    feistel.setKey(key);
}

size_t DES::getBlockSize() const
{
    return 8;
}

type DES::encrypt(const type& block)
{
    if (block.size() != getBlockSize()) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type permutedBlock = permuteBits(block, DESConstants::IP, BitIndexing::MSB_1);
    type encryptedBlock = feistel.encrypt(permutedBlock);

    std::swap_ranges( // конечная перестановка предусматривает не LR, а RL. начало первого, конец первого начало второго
        encryptedBlock.begin(),
        encryptedBlock.begin() + 4,
        encryptedBlock.begin() + 4
    );

    return permuteBits(encryptedBlock, DESConstants::IP_INVERSE, BitIndexing::MSB_1);
}

type DES::decrypt(const type& block)
{
    if (block.size() != getBlockSize()) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type permutedBlock = permuteBits(block, DESConstants::IP, BitIndexing::MSB_1);
    std::swap_ranges(
        permutedBlock.begin(),
        permutedBlock.begin() + 4,
        permutedBlock.begin() + 4
    );
    type decryptedBlock = feistel.decrypt(permutedBlock);
    return permuteBits(decryptedBlock, DESConstants::IP_INVERSE, BitIndexing::MSB_1);
}