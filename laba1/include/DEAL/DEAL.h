#pragma once

#include "interfaces/ISymmetricCipher.h"
#include "Feistel.h"
#include "DEAL/DEALKeyExpansion.h"
#include "DEAL/DEALRoundTransform.h"

class DEAL : public ISymmetricCipher {
private:
    DEALKeyExpansion keyExpansion;
    DEALRoundTransform roundTransform;
    Feistel feistel;

public:
    DEAL();

    void setKey(const type& key) override;

    size_t getBlockSize() const override;

    type encrypt(const type& block) override;

    type decrypt(const type& block) override;
};