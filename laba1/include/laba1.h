#pragma once

#include <vector>
#include <cstdint>

using type = std::vector<uint8_t>;

enum struct Error {
    ERROR_INDEXING,
    ERROR_INDEX,
    ERROR_SET_BIT,
    ERROR_INDEX_PBLOCK,
    ERROR_BLOCK_SIZE,
    ERROR_SYNTAX,
};

enum struct BitIndexing {
    MSB_0, // от страшего к младшему (слева направо)
    MSB_1,
    LSB_0, // справа налево
    LSB_1
};

bool getBit(
    const type& value,
    size_t index,
    BitIndexing bitindexing
);

bool setBit(
    type& result,
    size_t index,
    bool bit,
    BitIndexing bitindexing
);

type permuteBits(
    const type& value,
    const std::vector<size_t>& P_block,
    BitIndexing bitindexing
);

