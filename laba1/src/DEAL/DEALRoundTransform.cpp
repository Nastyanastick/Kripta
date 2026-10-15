#include "DEAL/DEALRoundTransform.h"
#include "DES/DES.h"

type DEALRoundTransform::transform(
    const type& inputBlock,
    const type& roundKey
)
{
    DES des;
    des.setKey(roundKey); // раундовый ключ DEAL
    return des.encrypt(inputBlock);
}
