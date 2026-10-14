#pragma once

#include <vector>
#include "laba1.h"
#include "IRoundTransform.h"

using type = std::vector<uint8_t>;

class DESRoundTransform : public IRoundTransform {
public:
    type transform(const type& inputBlock, const type& roundKey) override;  
};