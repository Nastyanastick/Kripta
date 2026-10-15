#pragma once

#include "interfaces/IRoundTransform.h"

class DEALRoundTransform : public IRoundTransform {
public:
    type transform(
        const type& inputBlock,
        const type& roundKey
    ) override;
};