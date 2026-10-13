#pragma once

#include <vector>
#include <cstdint>
#include "IKeyExpansion.h"

using type = std::vector<uint8_t>;

class DESKeyExpansion : public IKeyExpansion {
public:
    std::vector<type> generateRoundKeys(const type& key) override;
};