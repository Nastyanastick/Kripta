#include "Rijndael.h"
#include "Errors.h"

#include <stdexcept>

Rijndael::Rijndael(size_t blockSize, size_t keySize, type_8 fieldModulus, IKeyExpansion& keyExpansion)
    : blockSize(blockSize), keySize(keySize), fieldModulus(fieldModulus), keyExpansion(keyExpansion) {

    if (blockSize != 128 && blockSize != 192 && blockSize != 256) throw Error::INVALID_BLOCK_SIZE;
    if (keySize != 128 && keySize != 192 && keySize != 256) throw Error::INVALID_KEY_SIZE;
    if (!PolynomialArithmetic::IsIrreducible(fieldModulus)) throw Error::ERROR_REDUCIBLE_MODULUS;
}

void Rijndael::initializeSBox() {
    for (int i = 0; i < 256; i++) {
        type_8 inverse = 0;
        if (i != 0) {
            inverse = PolynomialArithmetic::InversePolynomial(static_cast<type_8>(i), fieldModulus);
        }
        type_8 temp = inverse;
        type_8 result = temp ^ static_cast<type_8>((temp << 1) | (temp >> 7))
        ^ static_cast<type_8>((temp << 2) | (temp >> 6))
        ^ static_cast<type_8>((temp << 3) | (temp >> 5))
        ^ static_cast<type_8>((temp << 4) | (temp >> 4))
        ^ 0x63;
        sBox[i] = result;
    }
    sBoxesInitialized = true;
}

void Rijndael::initializeInverseSBox() {
    for (int i = 0; i < 256; i++) {
        type_8 element = 0;
        type_8 value = static_cast<type_8>(i);
        type_8 temp = static_cast<type_8>((value << 1) | (value >> 7))
        ^ static_cast<type_8>((value << 3) | (value >> 5))
        ^ static_cast<type_8>((value << 6) | (value >> 2))
        ^ 0x05;
        if (temp != 0) {
            element = PolynomialArithmetic::InversePolynomial(temp, fieldModulus);
        }
        inverseSBox[i] = element;
    }
    sBoxesInitializedInverse = true;
}

type Rijndael::subBytes(const type& state) {
    if (!sBoxesInitialized) initializeSBox();
    type result = state;
    for(size_t i = 0; i < state.size(); i++) {
        result[i] = sBox[state[i]];
    }
    return result;
}

type Rijndael::inverseSubBytes(const type& state) {
    if (!sBoxesInitializedInverse) initializeInverseSBox();
    type result = state;
    for (size_t i = 0; i < state.size(); i++) {
        result[i] = inverseSBox[state[i]];
    }
    return result;
}

type Rijndael::shiftRows(const type& state) {
    type result = state;
    if (blockSize == 128) {
        for (size_t row = 0; row < 4; row++){
            for (size_t col = 0; col < 4; col++) {
                result[4 * col + row] = state[((row + col) % 4) * 4 + row];     // (col + row) % 4 - из какого столбца берем байт с учетом сдвига
            }
        }
    }
    if (blockSize == 192) {
        for (size_t row = 0; row < 4; row++) {
            for (size_t col = 0; col < 6; col++) {
                result[4 * col + row] = state[((row + col) % 6) * 4 + row];
            }
        }
    }
    if (blockSize == 256) {
        for (size_t row = 0; row < 4; row++) {
            for (size_t col = 0; col < 8; col++) {
                if (row == 0 || row == 1) result[4 * col + row] = state[((row + col) % 8) * 4 + row];
                else if (row == 2) result[4 * col + row] = state[((3 + col) % 8) * 4 + row];
                else result[4 * col + row] = state[((4 + col) % 8) * 4 + row];
            }
        }
    }
    return result;
}

type Rijndael::inverseShiftRows(const type& state) {
    type result = state;
    if (blockSize == 128) {
        for (size_t row = 0; row < 4; row++) {
            for (size_t col = 0; col < 4; col++) {
                result[4 * col + row] = state[((col + 4 - row) % 4) * 4 + row];
            }
        }
    }
    if (blockSize == 192) {
        for (size_t row = 0; row < 4; row++) {
            for (size_t col = 0; col < 6; col++) {
                result[4 * col + row] = state[((col + 6 - row) % 6) * 4 + row];
            }
        }
    }
    if (blockSize == 256) {
        for (size_t row = 0; row < 4; row++) {
            for (size_t col = 0; col < 8; col++) {
                if (row == 0 || row == 1) result[4 * col + row] = state[((col + 8 - row) % 8) * 4 + row];
                else if (row == 2) result[4 * col + row] = state[((col + 8 - 3) % 8) * 4 + row];
                else result[4 * col + row] = state[((col + 8 - 4) % 8) * 4 + row];
            }
        }
    }
    return result;
}

type Rijndael::mixColumns(const type& state) {
    type result = state;
    size_t nb = blockSize / 32;
    for (size_t col = 0; col < nb; col++) {
        type_8 a0 = state[4 * col];
        type_8 a1 = state[4 * col + 1];
        type_8 a2 = state[4 * col + 2];
        type_8 a3 = state[4 * col + 3];
        result[4 * col] = PolynomialArithmetic::AddPolynomial(
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::AddPolynomial(
                    PolynomialArithmetic::MultiplyPolynomial(0x02, a0, fieldModulus),
                    PolynomialArithmetic::MultiplyPolynomial(0x03, a1, fieldModulus)),
                a2),
            a3);

        result[4 * col + 1] = PolynomialArithmetic::AddPolynomial(
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::AddPolynomial(
                    a0,
                    PolynomialArithmetic::MultiplyPolynomial(0x02, a1, fieldModulus)),
                PolynomialArithmetic::MultiplyPolynomial(0x03, a2, fieldModulus)),
            a3);

        result[4 * col + 2] = PolynomialArithmetic::AddPolynomial(
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::AddPolynomial(a0, a1),
                PolynomialArithmetic::MultiplyPolynomial(0x02, a2, fieldModulus)),
            PolynomialArithmetic::MultiplyPolynomial(0x03, a3, fieldModulus));

        result[4 * col + 3] = PolynomialArithmetic::AddPolynomial(
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::AddPolynomial(
                    PolynomialArithmetic::MultiplyPolynomial(0x03, a0, fieldModulus),
                    a1),
                a2),
            PolynomialArithmetic::MultiplyPolynomial(0x02, a3, fieldModulus));
    }
    return result;
}

type Rijndael::inverseMixColumns(const type& state) {
    type result = state;
    size_t nb = blockSize / 32;
    for (size_t col = 0; col < nb; col++) {
        type_8 a0 = state[4 * col];
        type_8 a1 = state[4 * col + 1];
        type_8 a2 = state[4 * col + 2];
        type_8 a3 = state[4 * col + 3];
        result[4 * col] = PolynomialArithmetic::AddPolynomial(PolynomialArithmetic::AddPolynomial(
            PolynomialArithmetic::MultiplyPolynomial(0x0E, a0, fieldModulus),
            PolynomialArithmetic::MultiplyPolynomial(0x0B, a1, fieldModulus)),
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::MultiplyPolynomial(0x0D, a2, fieldModulus),
                PolynomialArithmetic::MultiplyPolynomial(0x09, a3, fieldModulus)
            ));

        result[4 * col + 1] = PolynomialArithmetic::AddPolynomial(
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::MultiplyPolynomial(0x09, a0, fieldModulus),
                PolynomialArithmetic::MultiplyPolynomial(0x0E, a1, fieldModulus)),
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::MultiplyPolynomial(0x0B, a2, fieldModulus),
                PolynomialArithmetic::MultiplyPolynomial(0x0D, a3, fieldModulus)
            ));

        result[4 * col + 2] = PolynomialArithmetic::AddPolynomial(
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::MultiplyPolynomial(0x0D, a0, fieldModulus),
                PolynomialArithmetic::MultiplyPolynomial(0x09, a1, fieldModulus)),
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::MultiplyPolynomial(0x0E, a2, fieldModulus),
                PolynomialArithmetic::MultiplyPolynomial(0x0B, a3, fieldModulus)
            ));

        result[4 * col + 3] = PolynomialArithmetic::AddPolynomial(
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::MultiplyPolynomial(0x0B, a0, fieldModulus),
                PolynomialArithmetic::MultiplyPolynomial(0x0D, a1, fieldModulus)),
            PolynomialArithmetic::AddPolynomial(
                PolynomialArithmetic::MultiplyPolynomial(0x09, a2, fieldModulus),
                PolynomialArithmetic::MultiplyPolynomial(0x0E, a3, fieldModulus)
            ));
    }
    return result;
}

void Rijndael::setKey(const type& key) {
    if (key.size() != keySize / 8) throw Error::ERROR_INVALID_KEY;
    roundKeys = keyExpansion.generateRoundKeys(key);
}

size_t Rijndael::getBlockSize() const {
    return blockSize / 8;
}

type Rijndael::encrypt(const type& block) {
    if (block.size() != blockSize / 8) throw Error::INVALID_BLOCK_SIZE;
    if (roundKeys.empty()) throw Error::ERROR_INVALID_KEY;
    size_t Nr = roundKeys.size() - 1;
    type state = block;
    for (size_t i = 0; i < state.size(); i++) {
        state[i] ^= roundKeys[0][i];
    }
    for (size_t round = 1; round < Nr; round++) {
        state = subBytes(state);
        state = shiftRows(state);
        state = mixColumns(state);

        for (size_t i = 0; i < state.size(); i++) {
            state[i] ^= roundKeys[round][i];
        }
    }
    state = subBytes(state);
    state = shiftRows(state);
    for (size_t i = 0; i < state.size(); i++) {
        state[i] ^= roundKeys[Nr][i];
    }
    return state;
}

type Rijndael::decrypt(const type& block) {
    if (block.size() != blockSize / 8) throw Error::INVALID_BLOCK_SIZE;
    if (roundKeys.empty()) throw Error::ERROR_INVALID_KEY;
    size_t Nr = roundKeys.size() - 1;
    type state = block;
    for (size_t i = 0; i < state.size(); i++) {
        state[i] ^= roundKeys[Nr][i];
    }
    for (size_t round = Nr - 1; round > 0; round--) {
        state = inverseShiftRows(state);
        state = inverseSubBytes(state);
        for (size_t i = 0; i < state.size(); i++) {
            state[i] ^= roundKeys[round][i];
        }
        state = inverseMixColumns(state);
    }
    state = inverseShiftRows(state);
    state = inverseSubBytes(state);
    for (size_t i = 0; i < state.size(); i++) {
        state[i] ^= roundKeys[0][i];
    }
    return state;
}