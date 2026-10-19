
#include "DEAL/DEALKeyExpansion.h"
#include "DES/DES.h"
#include "laba1.h"

#include <cstdint>
#include <vector>

namespace {

type xorBlocks(const type& a, const type& b)
{
    type result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

void xorConstant(type& block, uint8_t constant)
{
    block[0] ^= constant;
}

}

std::vector<type> DEALKeyExpansion::generateRoundKeys(
    const type& key
)
{
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw Error::ERROR_BLOCK_SIZE;
    }

    // Fixed DES key: 0123456789ABCDEF
    const type fixedKey = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    };

    DES des;
    des.setKey(fixedKey);

    const size_t keyParts = key.size() / 8;
    const size_t rounds = (keyParts == 4) ? 8 : 6;

    std::vector<type> keyBlocks;
    keyBlocks.reserve(keyParts);

    for (size_t i = 0; i < keyParts; ++i) {
        keyBlocks.emplace_back(key.begin() + i * 8, key.begin() + (i + 1) * 8);
    }

    std::vector<type> roundKeys;
    roundKeys.reserve(rounds);

    type previous;

    for (size_t i = 0; i < rounds; ++i) {
        type input = keyBlocks[i % keyParts];

        if (i > 0) {
            input = xorBlocks(input, previous);
        }

        if (i >= keyParts) {
            const uint8_t constant = static_cast<uint8_t>(0x80u >> (i - keyParts));

            xorConstant(input, constant);
        }
        previous = des.encrypt(input);
        roundKeys.push_back(previous);
    }

    return roundKeys;
}
