#pragma once

#include "IKeyExpansion.h"
#include "PolynomialArithmetic.h"
#include <functional>

class RijndaelKeyExpansion : public IKeyExpansion {
private:
    using size_t = std::size_t;
    size_t keySize;
    size_t blockSize;
    type_8 fieldModulus;
    std::function<type(const type&)> subBytes;

    type rotWord(const type& word);
    type xorWords(const type& word1, const type& word2);
    type generateRcon(type_8& roundConstant);

public:
    RijndaelKeyExpansion(size_t keySize, size_t blockSize, type_8 fieldModulus, std::function<type(const type&)> subBytes);
    std::vector<type> generateRoundKeys(const type& key) override;
};