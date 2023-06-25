#include "pg_facade.h"

class pg_x_attribute : public libaaa_pg_test {};

TEST_F(pg_x_attribute, extended_empty) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 23,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 3, 4,                // Att, Att-Length, E-Type
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin_extended(ctx, 3, 4), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 23);
    EXPECT_THAT(buffer, PacketCheck(expected, 23));
}

// We do ONE test for all data types (Types implementation is already tested)
TEST_F(pg_x_attribute, extended_types) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 92,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 72, 4,               // Att, Att-Length, E-Type

        0x11, 0x12, 0x13, 0x14, // Integer
        'H', 'e', 'l', 'l',     // String
        'o', '!',               // ...
        0xA0, 0xA1, 0xA2, 0xA3, // Data
        0xA4, 0xA5, 0xA6, 0xA7, // ...
        0xA8, 0xA9, 0xAA, 0xAB, // ...
        1, 2, 3, 4, 5, 6, 7, 8, // IFID
        192, 168, 10, 55,       // IPv4 Address
        0xfd, 0x92, 0x61, 0x5c, // IPv6 Address
        0xf7, 0x43, 0xf3, 0x9e, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0, 24, 192, 168, 10,    // IPv4 prefix
        0, 32,                  // IPv6 prefix
        0xfd, 0x92, 0x61, 0x5c, // ...
        0x10, 0x20, 0x30, 0x40, // Integer 64
        0x50, 0x60, 0x70, 0x80, // ...
    };

    uint8_t data[] = {
        0xA0, 0xA1, 0xA2, 0xA3, 
        0xA4, 0xA5, 0xA6, 0xA7, 
        0xA8, 0xA9, 0xAA, 0xAB, 
    };

    libaaa_ifid_t ifid{ 1, 2, 3, 4, 5, 6, 7, 8 };
    libaaa_ipv4addr_t ipv4addr{ 192, 168, 10, 55 };
    libaaa_ipv6addr_t ipv6addr{ 
        0xfd, 0x92, 0x61, 0x5c, 
        0xf7, 0x43, 0xf3, 0x9e, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin_extended(ctx, 3, 4), LIBAAA_OK);

    EXPECT_EQ(libaaa_pg_write_integer(ctx, 0x11121314), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_text(ctx, "Hello!", 6), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_string(ctx, data, 12), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ifid(ctx, ifid), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv4addr(ctx, ipv4addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv6addr(ctx, ipv6addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv4prefix(ctx, 24, ipv4addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv6prefix(ctx, 32, ipv6addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_integer64(ctx, 0x1020304050607080), LIBAAA_OK);

    EXPECT_EQ(libaaa_pg_finalize(ctx), 92);
    EXPECT_THAT(buffer, PacketCheck(expected, 92));
}

TEST_F(pg_x_attribute, long_extended_empty) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 24,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 4, 4, 0b00000000,    // Att, Att-Length, E-Type, MORE
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin_long_extended(ctx, 3, 4), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 24);
    EXPECT_THAT(buffer, PacketCheck(expected, 24));
}

// We do ONE test for all data types (Types implementation is already tested)
TEST_F(pg_x_attribute, long_extended_types) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 93,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 73, 4, 0b00000000,   // Att, Att-Length, E-Type, MORE

        0x11, 0x12, 0x13, 0x14, // Integer
        'H', 'e', 'l', 'l',     // String
        'o', '!',               // ...
        0xA0, 0xA1, 0xA2, 0xA3, // Data
        0xA4, 0xA5, 0xA6, 0xA7, // ...
        0xA8, 0xA9, 0xAA, 0xAB, // ...
        1, 2, 3, 4, 5, 6, 7, 8, // IFID
        192, 168, 10, 55,       // IPv4 Address
        0xfd, 0x92, 0x61, 0x5c, // IPv6 Address
        0xf7, 0x43, 0xf3, 0x9e, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0, 24, 192, 168, 10,    // IPv4 prefix
        0, 32,                  // IPv6 prefix
        0xfd, 0x92, 0x61, 0x5c, // ...
        0x10, 0x20, 0x30, 0x40, // Integer 64
        0x50, 0x60, 0x70, 0x80, // ...
    };

    uint8_t data[] = {
        0xA0, 0xA1, 0xA2, 0xA3, 
        0xA4, 0xA5, 0xA6, 0xA7, 
        0xA8, 0xA9, 0xAA, 0xAB, 
    };

    libaaa_ifid_t ifid{ 1, 2, 3, 4, 5, 6, 7, 8 };
    libaaa_ipv4addr_t ipv4addr{ 192, 168, 10, 55 };
    libaaa_ipv6addr_t ipv6addr{ 
        0xfd, 0x92, 0x61, 0x5c, 
        0xf7, 0x43, 0xf3, 0x9e, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin_long_extended(ctx, 3, 4), LIBAAA_OK);

    EXPECT_EQ(libaaa_pg_write_integer(ctx, 0x11121314), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_text(ctx, "Hello!", 6), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_string(ctx, data, 12), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ifid(ctx, ifid), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv4addr(ctx, ipv4addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv6addr(ctx, ipv6addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv4prefix(ctx, 24, ipv4addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_ipv6prefix(ctx, 32, ipv6addr), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_integer64(ctx, 0x1020304050607080), LIBAAA_OK);

    EXPECT_EQ(libaaa_pg_finalize(ctx), 93);
    EXPECT_THAT(buffer, PacketCheck(expected, 93));
}

TEST_F(pg_x_attribute, long_extended_more)
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0x01, 0x1C,             // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        3, 255, 4, 0b10000000,  // Att, Att-Length, E-Type, MORE
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32 x 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                // 27 x 0
        3, 9, 4, 0b00000000,   // Att, Att-Length, E-Type, MORE
        0, 0, 0, 0, 0,
    };

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
    EXPECT_EQ(libaaa_pg_attribute_begin_long_extended(ctx, 3, 4), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_write_string(ctx, data, 256), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 284);
    EXPECT_THAT(buffer, PacketCheck(expected, 284));
} 

// We will only test empty packets with vendored. All other cases are already covered
TEST_F(pg_x_attribute, vendor_empty) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 26,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        26, 6,                  // Att, Att-Length 
        0x01, 0x02, 0x03, 0x04, // Vendor ID
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin_vendor_specific(ctx, 0x01020304), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 26);
    EXPECT_THAT(buffer, PacketCheck(expected, 26));
}

TEST_F(pg_x_attribute, vendor_extended_empty) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 28,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        241, 8, 26,             // Att, Att-Length, E-Type
        0x01, 0x02, 0x03, 0x04, // Vendor ID
        4,                      // Vendor Type
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin_extended_vendor_specific(ctx, LIBAAA_RADIUS_ATTRIBUTE_TYPE_EXTENDED_VENDOR_SPECIFIC_1, 0x01020304, 4), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 28);
    EXPECT_THAT(buffer, PacketCheck(expected, 28));
}

TEST_F(pg_x_attribute, vendor_long_extended_empty) 
{
    // Expected packet
    uint8_t expected[] = {
        1, 2,                   // Code, ID
        0, 29,                  // Length 
        0, 0, 0, 0, 0, 0, 0, 0, // Authenticator
        0, 0, 0, 0, 0, 0, 0, 0, // ...
        246, 9, 26, 0b00000000, // Att, Att-Length, E-Type, More
        0x01, 0x02, 0x03, 0x04, // Vendor ID
        4,                      // Vendor Type
    };

    libaaa_pg_reset(ctx, 1, 2);
    EXPECT_EQ(libaaa_pg_attribute_begin_extended_vendor_specific(ctx, LIBAAA_RADIUS_ATTRIBUTE_TYPE_EXTENDED_VENDOR_SPECIFIC_6, 0x01020304, 4), LIBAAA_OK);
    EXPECT_EQ(libaaa_pg_finalize(ctx), 29);
    EXPECT_THAT(buffer, PacketCheck(expected, 29));
}
