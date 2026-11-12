#include "RijndaelKeyExpansion.h"


type RijndaelKeyExpansion::rotWord(const type& word) {
    return {word[1], word[2], word[3], word[0]};
}

type RijndaelKeyExpansion::xorWords(const type& word1, const type& word2) {
    type result(4);
    for (size_t i = 0; i < 4; i++) result[i] = word1[i] ^ word2[i];
    return result;
}

type RijndaelKeyExpansion::generateRcon(type_8& roundConstant) {
    type result = {roundConstant, 0x00, 0x00, 0x00};
    roundConstant = PolynomialArithmetic::MultiplyPolynomial(0x02, roundConstant, fieldModulus);
    return result;
}

RijndaelKeyExpansion::RijndaelKeyExpansion(size_t keySize, size_t blockSize, type_8 fieldModulus, std::function<type(const type&)> subBytes)
    : keySize(keySize), blockSize(blockSize), fieldModulus(fieldModulus), subBytes(subBytes) {}

std::vector<type> RijndaelKeyExpansion::generateRoundKeys(const type& key) {
    if (key.size() != keySize / 8) throw Error::ERROR_INVALID_KEY;
    size_t Nk = keySize / 32;
    size_t Nb = blockSize / 32;
    size_t Nr = std::max(Nk, Nb) + 6;
    std::vector<type> words;
    for (size_t i = 0; i < Nk; i++) {
        type word;
        for (size_t j = 0; j < 4; j++) word.push_back(key[4 * i + j]);
        words.push_back(word);
    }
    type_8 roundConstant = 0x01;

    for (size_t i = Nk; i < Nb * (Nr + 1); i++) {
        type temp = words[i - 1];
        if (i % Nk == 0) {
            temp = rotWord(temp);
            temp = subBytes(temp);
            temp = xorWords(temp, generateRcon(roundConstant));
        }
        else if (Nk == 8 && i % Nk == 4) temp = subBytes(temp);
        words.push_back(xorWords(words[i - Nk], temp));
    }
    std::vector<type> roundKeys;
    for (size_t i = 0; i < Nr + 1; i++) {
        type roundKey;
        for (size_t j = 0; j < Nb; j++) {
            for (size_t k = 0; k < 4; k++) {
                roundKey.push_back(words[i * Nb + j][k]);
            }
        }
        roundKeys.push_back(roundKey);
    }
    return roundKeys;
}