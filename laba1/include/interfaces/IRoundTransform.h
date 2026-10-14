#pragma once

#include <vector>
#include <cstdint>

using type = std::vector<uint8_t>;

class IRoundTransform {
public:
    virtual type transform(
        const type& inputBlock,
        const type& roundKey
    ) = 0;

    virtual ~IRoundTransform() = default;
};