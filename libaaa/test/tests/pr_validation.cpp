#include "pr_facade.h"

class pr_validation : public libaaa_pr_test {};

TEST_F(pr_validation, size_invalid)
{
    // Retrieve packet
    uint8_t packet[] = {
        0, 0, 0, 0,
    };

    EXPECT_EQ(libaaa_pr_validate_packet(packet, 4), LIBAAA_PACKET_INVALID_LENGTH);
}

TEST_F(pr_validation, header_valid)
{
    // Retrieve packet
    uint8_t packet[] = {
        1, 2,                   // Code, ID
        0, 20,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
    };

    EXPECT_EQ(libaaa_pr_validate_packet(packet, 20), LIBAAA_OK);
}

TEST_F(pr_validation, header_valid_padding)
{
    // Retrieve packet
    uint8_t packet[] = {
        1, 2,                   // Code, ID
        0, 20,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0,
    };

    EXPECT_EQ(libaaa_pr_validate_packet(packet, 32), LIBAAA_OK);
}

TEST_F(pr_validation, header_invalid)
{
    // Retrieve packet
    uint8_t packet[] = {
        160, 2,                 // Code, ID
        0, 20,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
    };

    EXPECT_EQ(libaaa_pr_validate_packet(packet, 20), LIBAAA_PACKET_VALIDATION_FAILED);
}

TEST_F(pr_validation, attribute_valid)
{
    // Retrieve packet
    uint8_t packet[] = {
        1, 2,                   // Code, ID
        0, 22,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 2,
    };

    EXPECT_EQ(libaaa_pr_validate_packet(packet, 22), LIBAAA_OK);
}

TEST_F(pr_validation, attribute_invalid)
{
    // Retrieve packet
    uint8_t packet[] = {
        1, 2,                   // Code, ID
        0, 22,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 0,
    };

    EXPECT_EQ(libaaa_pr_validate_packet(packet, 22), LIBAAA_PACKET_INVALID_BODY);
}

TEST_F(pr_validation, attribute_header_missmatch)
{
    // Retrieve packet
    uint8_t packet[] = {
        1, 2,                   // Code, ID
        0, 22,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 5, 0, 0, 0,          // <-- Valid attributes but invalid header size
    };

    EXPECT_EQ(libaaa_pr_validate_packet(packet, 25), LIBAAA_PACKET_INVALID_BODY);
}
