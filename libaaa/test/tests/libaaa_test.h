#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <libaaa/libaaa.h>

MATCHER_P2(PacketCheck, expected, length, "")
{
    for(size_t i = 0; i < length; ++i)
    {
        if(((uint8_t*)arg)[i] != ((uint8_t*)expected)[i])
        {
            // printf("Mismatch at position %i (Was: %#02x should be %#02x)\n", i, ((uint8_t*)arg)[i], ((uint8_t*)expected)[i]);
            return false;
        }
    }
    return true;
}

