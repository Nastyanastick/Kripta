#include "DES/DESKeyExpansion.h"
#include "laba1.h"
#include "DES/DESConstants.h"

type leftShift28(const type& value, size_t shift) {
    type result(4, 0);
    for (size_t i = 0; i < 28; i++) {
        bool bit = getBit(value, i + 1, BitIndexing::MSB_1);
        size_t newIndex = (i + 28 - shift) % 28;
        setBit(result, newIndex + 1, bit, BitIndexing::MSB_1);
    }
    return result;
}

type combineHalves28(const type& C, const type& D)
{
    type result(7, 0);

    for (size_t i = 0; i < 28; i++) {
        bool bit = getBit(C, i + 1, BitIndexing::MSB_1);
        setBit(result, i + 1, bit, BitIndexing::MSB_1);
    }

    for (size_t i = 0; i < 28; i++) {
        bool bit = getBit(D, i + 1, BitIndexing::MSB_1);
        setBit(result, i + 29, bit, BitIndexing::MSB_1);
    }

    return result;
}

std::vector<type> DESKeyExpansion::generateRoundKeys(const type& key)
{
    if (key.size() != 8) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    type key56 = permuteBits(key, DESConstants::PC1, BitIndexing::MSB_1);
    type C = permuteBits(key56, DESConstants::C_positions, BitIndexing::MSB_1);
    type D = permuteBits(key56, DESConstants::D_positions, BitIndexing::MSB_1);

    std::vector<type> K_rounds;

    for (size_t round = 0; round < 16; round++) {
        type new_C = leftShift28(C, DESConstants::SHIFT[round]);
        type new_D = leftShift28(D, DESConstants::SHIFT[round]);
        C = new_C;
        D = new_D;
        type temp = combineHalves28(new_C, new_D);
        type newKey = permuteBits(temp, DESConstants::PC2, BitIndexing::MSB_1);
        K_rounds.push_back(newKey);
    }
    return K_rounds;
}