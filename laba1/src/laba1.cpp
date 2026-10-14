#include "laba1.h"

size_t byteIndex (size_t index, BitIndexing bitindexing){
    if (bitindexing == BitIndexing::MSB_0 ||
        bitindexing == BitIndexing::LSB_0) return index / 8;

    if (bitindexing == BitIndexing::MSB_1 ||
        bitindexing == BitIndexing::LSB_1){
        if (index == 0) { throw Error::ERROR_INDEX; }
        index --;
        return index / 8;
    }
    throw Error::ERROR_SYNTAX;
}

size_t bitIndex (size_t index, BitIndexing bitindexing){
    if (bitindexing == BitIndexing::MSB_0 ||
        bitindexing == BitIndexing::LSB_0) return index % 8;

    if (bitindexing == BitIndexing::MSB_1 ||
        bitindexing == BitIndexing::LSB_1){
        if (index == 0) { throw Error::ERROR_INDEX; }
        index --;
        return index % 8;
    }
    throw Error::ERROR_SYNTAX;
}

bool getBit(
    const type& value,
    size_t index,
    BitIndexing bitindexing
){

    size_t byte_Index;
    size_t bit_Index;

    if (bitindexing == BitIndexing::MSB_0){
        byte_Index = byteIndex(index, bitindexing);
        bit_Index = bitIndex(index, bitindexing);

        return ((value[byte_Index] >> (7 - bit_Index)) & 1);
    }
    else if (bitindexing == BitIndexing::MSB_1){
        byte_Index = byteIndex(index, bitindexing);
        bit_Index = bitIndex(index, bitindexing);

        return ((value[byte_Index] >> (7 - bit_Index)) & 1);
    }
    else if (bitindexing == BitIndexing::LSB_0){
        byte_Index = byteIndex(index, bitindexing);
        bit_Index = bitIndex(index, bitindexing);

        return ((value[byte_Index] >> bit_Index) & 1);
    }
    else if (bitindexing == BitIndexing::LSB_1){
        byte_Index = byteIndex(index, bitindexing);
        bit_Index = bitIndex(index, bitindexing);

        return ((value[byte_Index] >> bit_Index) & 1);
    }
    else {
        throw Error::ERROR_INDEXING;
    }
}

bool setBit(
    type& result,
    size_t index,
    bool bit,
    BitIndexing bitindexing
){
    size_t byte_Index;
    size_t bit_Index;
    if (bitindexing == BitIndexing::MSB_0 || bitindexing == BitIndexing::MSB_1){
        byte_Index = byteIndex(index, bitindexing);
        bit_Index = bitIndex(index, bitindexing);
        if (bit == 1){
            result[byte_Index] |= (1 << (7 - bit_Index));
            return true;
        }
        if (bit == 0){
            result[byte_Index] &= ~(1 << (7 - bit_Index));
            return true;
        }
    }

    if (bitindexing == BitIndexing::LSB_0 || bitindexing == BitIndexing::LSB_1){
        byte_Index = byteIndex(index, bitindexing);
        bit_Index = bitIndex(index, bitindexing);
        if (bit == 1){
            result[byte_Index] |= (1 << bit_Index);
            return true;
        }
        if (bit == 0){
            result[byte_Index] &= ~(1 << bit_Index);
            return true;
        }
    }
    return false;
}

type permuteBits(
    const type& value,
    const std::vector<size_t>& P_block,
    BitIndexing bitindexing
){
    size_t resultSize = (P_block.size() + 7) / 8;
    type result(resultSize);
    for (size_t i = 0; i < P_block.size(); i++) {
        if ((bitindexing == BitIndexing::MSB_0 ||
            bitindexing == BitIndexing::LSB_0) && 
            P_block[i] >= value.size() * 8) { throw Error::ERROR_INDEX_PBLOCK; }
        else if ((bitindexing == BitIndexing::MSB_1 ||
            bitindexing == BitIndexing::LSB_1) &&
            (P_block[i] == 0 || P_block[i] > value.size() * 8)) {
                throw Error::ERROR_INDEX_PBLOCK;
        }

        size_t resultIndex = i;

        if (bitindexing == BitIndexing::MSB_1 ||
            bitindexing == BitIndexing::LSB_1) { resultIndex++; }
        bool bit = getBit(value, P_block[i], bitindexing); // получили значение бита который будем заменять
        if (!setBit(result, resultIndex, bit, bitindexing)) {
            throw Error::ERROR_SET_BIT;
        }
    }
    return result;
}