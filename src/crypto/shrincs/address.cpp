#include "address.h"

#include <crypto/common.h>

namespace Address
{
    void setLayerAddress(unsigned char* adrs, uint8_t layer)
    {
        memcpy(adrs, &layer, sizeof(layer));
    }

    void setTreeAddress(unsigned char* adrs, uint64_t tree_addr)
    {
        WriteBE64(adrs + 1, tree_addr);
    }

    void setType(unsigned char* adrs, uint8_t type)
    {
        memcpy(adrs + 9, &type, sizeof(type));
    }

    void set_10_14(unsigned char* adrs, uint32_t value)
    {
        WriteBE32(adrs + 10, value);
    }

    void set_14_18(unsigned char* adrs, uint32_t value)
    {
        WriteBE32(adrs + 14, value);
    }

    void set_14_22(unsigned char* adrs, uint64_t value)
    {
        WriteBE64(adrs + 14, value);
    }

    void set_18_22(unsigned char* adrs, uint32_t value)
    {
        WriteBE32(adrs + 18, value);
    }
}
