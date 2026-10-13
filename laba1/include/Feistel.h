#include <vector>
#include <cstdint>
#include "IKeyExpansion.h"
#include "IRoundTransform.h"
#include "ISymmetricCipher.h"

using type = std::vector<uint8_t>;

class Feistel : public ISymmetricCipher {
private:
    IKeyExpansion& keyExpansion;
    IRoundTransform& roundTransform;

    std::vector<type> roundKeys;

    type processBlock(
        const type& block,
        bool decrypt
    );

public:
    Feistel (
        IKeyExpansion& keyExpansion,
        IRoundTransform& roundTransform
    );

    void setKey(
        const type& key
    ) override;

    size_t getBlockSize() const override;

    type encrypt(
        const type& block
    ) override;

    type decrypt(
        const type& block
    ) override;

};