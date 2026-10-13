#include <vector>
#include <cstdint>

using type = std::vector<uint8_t>;

class IKeyExpansion {
public:
    virtual std::vector<type> generateRoundKeys(const type& key) = 0;

    virtual ~IKeyExpansion() = default;
};