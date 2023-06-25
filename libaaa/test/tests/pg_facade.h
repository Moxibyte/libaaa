#include "libaaa_test.h"

class libaaa_pg_test : public ::testing::Test
{
    protected:
        char ctx[LIBAAA_PG_CONTEXT_SIZE];
        char buffer[LIBAAA_PACKET_MAX_SIZE];

        virtual void SetUp() override
        {
            memset(buffer, 0xAD, LIBAAA_PACKET_MAX_SIZE);
            libaaa_pg_init(ctx, buffer, LIBAAA_PACKET_MAX_SIZE);
        }
};
