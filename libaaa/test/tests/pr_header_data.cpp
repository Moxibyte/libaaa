#include "pr_facade.h"

class pr_header_data : public libaaa_pr_test {};

TEST_F(pr_header_data, extract)
{
    // Expected values
    uint8_t expected_code = 22;
    uint8_t expected_id = 111;
    uint8_t expected_authenticator[] = {
        0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A, 0x8A,
        0x1B, 0x2B, 0x3B, 0x4B, 0x5B, 0x6B, 0x7B, 0x8B,
    };

    // Target values
    uint8_t code = 0;
    uint8_t id = 0;
    uint8_t authenticator[16];
    memset(authenticator, 0x0, 16);

    // Retrieve packet
    uint8_t packet[] = {
        22, 111,                                        // Code, ID
        0, 20,                                          // Length 
        0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A, 0x8A, // Authenticator
        0x1B, 0x2B, 0x3B, 0x4B, 0x5B, 0x6B, 0x7B, 0x8B, // ...
    };

    libaaa_pr_get_packet_details(packet, &code, &id, (char*)authenticator);

    EXPECT_EQ(code, expected_code);
    EXPECT_EQ(id, expected_id);
    ASSERT_THAT(authenticator, PacketCheck(expected_authenticator, 16));
}
