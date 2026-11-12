#pragma once 

#include <vector>
#include <array>
#include "ISymmetricCipher.h"
#include "IKeyExpansion.h"
#include "PolynomialArithmetic.h"

class Rijndael : public ISymmetricCipher {
private:
    using size_t = std::size_t;
    size_t blockSize;
    size_t keySize;
    type_8 fieldModulus;
    std::vector<type> roundKeys;
    std::array<type_8, 256> sBox;
    std::array<type_8, 256> inverseSBox;
    IKeyExpansion& keyExpansion;
    bool sBoxesInitialized = false;
    bool sBoxesInitializedInverse = false;

    void initializeSBox();
    void initializeInverseSBox();
    type inverseSubBytes(const type& state);
    type shiftRows(const type& state);
    type inverseShiftRows(const type& state);
    type mixColumns(const type& state);
    type inverseMixColumns(const type& state);

public:
    type subBytes(const type& state);
    Rijndael(size_t blockSize, size_t keySize, type_8 fieldModulus, IKeyExpansion& keyExpansion);
    void setKey (const type& key) override;
    size_t getBlockSize() const override;
    type encrypt (const type& block) override;
    type decrypt (const type& block) override;
};