#include "DES/DESRoundTransform.h"
#include "laba1.h"
#include "DES/DESConstants.h"

type DESRoundTransform::transform(const type& inputBlock, const type& roundKey) {
    type expended = permuteBits(inputBlock, DESConstants::E, BitIndexing::MSB_1);
    type xored = expended;
    for (size_t i = 0; i < xored.size(); i++) {
        xored[i] ^= roundKey[i];
    }
    type temp(4, 0);
    type result;

    for (size_t i = 0; i < 48; i += 6) {
        bool b1 = getBit(xored, i + 1, BitIndexing::MSB_1);
        bool b2 = getBit(xored, i + 2, BitIndexing::MSB_1);
        bool b3 = getBit(xored, i + 3, BitIndexing::MSB_1);
        bool b4 = getBit(xored, i + 4, BitIndexing::MSB_1);
        bool b5 = getBit(xored, i + 5, BitIndexing::MSB_1);
        bool b6 = getBit(xored, i + 6, BitIndexing::MSB_1);
        size_t row = b1 * 2 + b6;
        size_t stb = b2 * 8 + b3 * 4 + b4 * 2 + b5;
        size_t SBoxIndex = i / 6;
        size_t value = DESConstants::S_BOX[SBoxIndex][row][stb];

        for (int bit = 3; bit >= 0; bit--) {
            bool b = (value >> bit) & 1;
            size_t position = (i / 6) * 4 + (3 - bit); // i - 6 текущий S блок; начало четырехбитного участка и наш текущий bit
            setBit(temp, position + 1, b, BitIndexing::MSB_1);
        }
    }
    
    result = permuteBits(temp, DESConstants::P_BLOCK, BitIndexing::MSB_1);
    return result;
}

