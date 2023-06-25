#include "pg_facade.h"

class pg_empty : public libaaa_pg_test {};

// This test will verify that a minimal packet has 20 bytes
TEST_F(pg_empty, size) 
{  
    libaaa_pg_reset(ctx, 0, 0);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 20);
}

// This test will verify the integrity of a packet WITHOUT authenticator
TEST_F(pg_empty, packet_no_authenticator)
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 20,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 20);
    EXPECT_THAT(buffer, PacketCheck(expected, 20));
} 

// This test will verify the integrity of a packet WITH authenticator
TEST_F(pg_empty, packet_with_authenticator)
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                                               // Code, ID
        0, 20,                                              // Length 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,     // Authenticator
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,     // ...
    };

    libaaa_pg_reset(ctx, 1, 2);
    libaaa_pg_set_authenticator(ctx, &expected[4]);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 20);
    EXPECT_THAT(buffer, PacketCheck(expected, 20));
} 
