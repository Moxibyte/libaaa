#include "pg_facade.h"

class pg_attribute : public libaaa_pg_test {};

TEST_F(pg_attribute, empty) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 22,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 2,                   // Att, Att-Length 
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 3), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 22);
    EXPECT_THAT(buffer, PacketCheck(expected, 22));
}

TEST_F(pg_attribute, type_integer) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 26,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 6,                   // Att, Att-Length
        0b10000000, 0b11000000, // VALUE
        0b11100000, 0b11110000, // ...
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 3), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_integer(ctx, 2160124144ULL), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 26);
    EXPECT_THAT(buffer, PacketCheck(expected, 26));
}

TEST_F(pg_attribute, type_time) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 26,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 6,                   // Att, Att-Length
        0x39, 0x1A, 0x95, 0x8C, // VALUE
    };

    // Generate time
    std::tm tm{};
    tm.tm_year = 2000-1900; // 2000
    tm.tm_mon = 5-1;        // MAY
    tm.tm_mday = 11;        // 11 DoM
    tm.tm_hour = 12;        // 12
    tm.tm_min = 12;         // 12
    tm.tm_sec = 12;         // 12
    tm.tm_isdst = 0;
    std::time_t t = std::mktime(&tm); 

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_time(ctx, t), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 26);
    EXPECT_THAT(buffer, PacketCheck(expected, 26));
}

TEST_F(pg_attribute, type_text) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 34,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 14,                  // Att, Att-Length
        'H', 'e', 'l', 'l',     // VALUE
        'o', ' ', 'W', 'o',     //
        'r', 'l', 'd', '!',     //
    };

    const char* text = "Hello World!";

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_text(ctx, text, (int)strlen(text)), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 34);
    EXPECT_THAT(buffer, PacketCheck(expected, 34));
}

TEST_F(pg_attribute, type_string) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 34,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 14,                  // Att, Att-Length
        0x1A, 0x1B, 0x1C, 0x1D, // VALUE
        0x2A, 0x2B, 0x2C, 0x2D, //
        0x3A, 0x3B, 0x3C, 0x3D, //
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_string(ctx, &expected[22], 12), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 34);
    EXPECT_THAT(buffer, PacketCheck(expected, 34));
}

TEST_F(pg_attribute, type_ifid) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 30,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 10,                  // Att, Att-Length
        0x61, 0x62, 0x63, 0x64, // VALUE
        0x71, 0x72, 0x73, 0x74, //
    };

    libaaa_ifid_t ifid{ 0x61, 0x62, 0x63, 0x64, 0x71, 0x72, 0x73, 0x74 };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ifid(ctx, ifid), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 30);
    EXPECT_THAT(buffer, PacketCheck(expected, 30));
}

TEST_F(pg_attribute, type_ipv4addr) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 26,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 6,                   // Att, Att-Length
        192, 168, 10, 1,        // VALUE
    };

    libaaa_ipv4addr_t ipv4addr{ 192, 168, 10, 1 };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv4addr(ctx, ipv4addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 26);
    EXPECT_THAT(buffer, PacketCheck(expected, 26));
}

TEST_F(pg_attribute, type_ipv6addr) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 38,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 18,                  // Att, Att-Length
        0xfd, 0x92, 0x61, 0x5c, // VALUE
        0xf7, 0x43, 0xf3, 0x9e, //
        0xff, 0xff, 0xff, 0xff, //
        0xff, 0xff, 0xff, 0xff, //
    };

    libaaa_ipv6addr_t ipv6addr{ 
        0xfd, 0x92, 0x61, 0x5c, 
        0xf7, 0x43, 0xf3, 0x9e, 
        0xff, 0xff, 0xff, 0xff, 
        0xff, 0xff, 0xff, 0xff,
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv6addr(ctx, ipv6addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 38);
    EXPECT_THAT(buffer, PacketCheck(expected, 38));
}

TEST_F(pg_attribute, type_ipv6prefix_60)
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 32,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 12,                  // Att, Att-Length
        0x00, 60,               // VALUE
        0xfd, 0x92, 0x61, 0x5c, //
        0xf7, 0x43, 0xf3, 0x90, // 
    };

    libaaa_ipv6addr_t ipv6prefix{ 
        0xfd, 0x92, 0x61, 0x5c, 
        0xf7, 0x43, 0xf3, 0x9e, 
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv6prefix(ctx, 60, ipv6prefix), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 32);
    EXPECT_THAT(buffer, PacketCheck(expected, 32));
}

TEST_F(pg_attribute, type_ipv6prefix_64)
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 32,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 12,                  // Att, Att-Length
        0x00, 64,               // VALUE
        0xfd, 0x92, 0x61, 0x5c, // 
        0xf7, 0x43, 0xf3, 0x9e, // 
    };

    libaaa_ipv6addr_t ipv6prefix{ 
        0xfd, 0x92, 0x61, 0x5c, 
        0xf7, 0x43, 0xf3, 0x9e, 
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv6prefix(ctx, 64, ipv6prefix), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 32);
    EXPECT_THAT(buffer, PacketCheck(expected, 32));
}

TEST_F(pg_attribute, type_ipv4prefix_24) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 27,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 7,                   // Att, Att-Length
        0, 24,                  // VALUES
        192, 168, 10,           // 
    };

    libaaa_ipv4addr_t ipv4prefix{ 192, 168, 10, 0x00 };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv4prefix(ctx, 24, ipv4prefix), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 27);
    EXPECT_THAT(buffer, PacketCheck(expected, 27));
}

TEST_F(pg_attribute, type_ipv4prefix_28) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 28,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        5, 8,                   // Att, Att-Length
        0, 28,                  // VALUES
        192, 168, 10, 0xF0      // 
    };

    libaaa_ipv4addr_t ipv4prefix{ 192, 168, 10, 0xFF };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv4prefix(ctx, 28, ipv4prefix), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 28);
    EXPECT_THAT(buffer, PacketCheck(expected, 28));
}

TEST_F(pg_attribute, type_integer64) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 30,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 10,                  // Att, Att-Length
        0b10000000, 0b11000000, // VALUE
        0b11100000, 0b11110000, // ...
        0b11111000, 0b11111100, // ...
        0b11111110, 0b11111111, // ...
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 3), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_integer64(ctx, -9169081515752227073), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 30);
    EXPECT_THAT(buffer, PacketCheck(expected, 30));
}

TEST_F(pg_attribute, type_string_concat)
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0x01, 0x18,             // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 255,                 // Att, Att-Length
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,          // 29 x 0
        3, 5,                   // Att, Att-Length
        0, 0, 0,                // 3 x 0
    };

    // Data
    uint8_t data[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 3), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_string(ctx, data, 256), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 280);
    EXPECT_THAT(buffer, PacketCheck(expected, 280));
}

TEST_F(pg_attribute, multiple)
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 38,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 6,                   // Att, Att-Length
        0xA1, 0xA1, 0xA1, 0xA1, // VALUE 
        4, 6,                   // Att, Att-Length
        0xA2, 0xA2, 0xA2, 0xA2, // VALUE 
        5, 6,                   // Att, Att-Length
        0xA3, 0xA3, 0xA3, 0xA3, // VALUE 
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 3), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_integer(ctx, 0xA1A1A1A1), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 4), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_integer(ctx, 0xA2A2A2A2), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 5), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_integer(ctx, 0xA3A3A3A3), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 38);
    EXPECT_THAT(buffer, PacketCheck(expected, 38));
}

TEST_F(pg_attribute, attribute_overflow)
{
    char data[500];

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 3), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_text(ctx, data, 500), LIBAAA_ERROR);
}

TEST_F(pg_attribute, packet_overflow)
{
    libaaa_pg_reset(ctx, 1, 2);

    int ec;
    for(int i = 0; i < 4096 - 20; i = i + 6)
    {
        EXPECT_EQ(libaaa_pg_attribute_begin(ctx, 3), LIBAAA_OK);
        ec = libaaa_pg_write_integer(ctx, 0xA1A1A1A1);
    }

    EXPECT_EQ(ec, LIBAAA_ERROR);
}
