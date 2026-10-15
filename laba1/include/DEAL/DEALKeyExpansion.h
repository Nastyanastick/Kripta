#pragma once

#include "interfaces/IKeyExpansion.h"

class DEALKeyExpansion : public IKeyExpansion {
public:
    std::vector<type> generateRoundKeys(const type& key) override;
};
