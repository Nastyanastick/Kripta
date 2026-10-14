#pragma once

#include "interfaces/ISymmetricCipher.h"
#include "Feistel.h"
#include "DESKeyExpansion.h"
#include "DESRoundTransform.h"

class DES : public ISymmetricCipher {
private:
    DESKeyExpansion keyExpansion;
    DESRoundTransform roundTransform;
    Feistel feistel;

public:
    DES();

    void setKey(const type& key) override;

    size_t getBlockSize() const override;

    type encrypt(const type& block) override;

    type decrypt(const type& block) override;
};