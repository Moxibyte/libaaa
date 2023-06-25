/*
 *   https://libaaa.cc main SORUCE file.
 *   libaaa is a simple radius protocol library written in pure c
 *
 *   Please visit https://libaaa.cc for more information and support!
 *
 *   (C) Copyright 2023 Moxibyte GmbH https://moxibyte.com <webadmin@moxibyte.com>
 *
 *   Published under the "Boost Software License 1.0"
 *   Boost Software License - Version 1.0 - August 17th, 2003
 *
 *   Permission is hereby granted, free of charge, to any person or organization
 *   obtaining a copy of the software and accompanying documentation covered by
 *   this license (the "Software") to use, reproduce, display, distribute,
 *   execute, and transmit the Software, and to prepare derivative works of the
 *   Software, and to permit third-parties to whom the Software is furnished to
 *   do so, all subject to the following:
 *
 *   The copyright notices in the Software and this entire statement, including
 *   the above license grant, this restriction and the following disclaimer,
 *   must be included in all copies of the Software, in whole or in part, and
 *   all derivative works of the Software, unless such copies or derivative
 *   works are solely in the form of machine-executable object code generated by
 *   a source language processor.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
 *   SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
 *   FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
 *   ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *   DEALINGS IN THE SOFTWARE.
 *
 */
#include "libaaa/libaaa.h"

//
// === Generate defines base on top defined defines ===
//
#ifdef LIBAAA_LITTLE_ENDIAN
#define __LIBAAA_NET_SWAP_BYTES
#endif

//
// === Internal constants
//
#define __LIBAAA_PO_HEADER_CODE 0
#define __LIBAAA_PO_HEADER_IDENTIFIER 1
#define __LIBAAA_PO_HEADER_LENGTH 2
#define __LIBAAA_PO_HEADER_AUTHENTICATOR 4
#define __LIBAAA_PO_HEADER_FIRST_ATTRIBUTE 20

#define __LIBAAA_PO_ATTRIBUTE_TYPE 0
#define __LIBAAA_PO_ATTRIBUTE_LENGTH 1
#define __LIBAAA_PO_ATTRIBUTE_VALUE 2

#define __LIBAAA_PO_ATTRIBUTE_EXT_TYPE 0
#define __LIBAAA_PO_ATTRIBUTE_EXT_LENGTH 1
#define __LIBAAA_PO_ATTRIBUTE_EXT_EXT_TYPE 2
#define __LIBAAA_PO_ATTRIBUTE_EXT_VALUE 3

#define __LIBAAA_PO_ATTRIBUTE_LONG_EXT_TYPE 0
#define __LIBAAA_PO_ATTRIBUTE_LONG_EXT_LENGTH 1
#define __LIBAAA_PO_ATTRIBUTE_LONG_EXT_EXT_TYPE 2
#define __LIBAAA_PO_ATTRIBUTE_LONG_EXT_EXT_TYPE_FLAGS 3
#define __LIBAAA_PO_ATTRIBUTE_LONG_EXT_VALUE 4

#define __LIBAAA_CTX_ATS_NONE 0
#define __LIBAAA_CTX_ATS_NORMAL 1
#define __LIBAAA_CTX_ATS_EXTENDED 2
#define __LIBAAA_CTX_ATS_LONG_EXTENDED 3

#define _LIBAAA_ATTR_NORMAL_DOFFSET 2

//
// === Internal types
//
typedef struct __libaaa_pg_context
{
    // Buffer properties
    uint8_t* buffer;
    uint16_t buffer_size;
    uint16_t buffer_head;

    // Attribute staging
    uint16_t ats_type;
    uint16_t ats_base;
    uint16_t ats_capacity;

} __libaaa_pg_context_t;

//
// === Internal function prototypes ===
// 
void __libaaa_byte_swap(const char* in, char* out, uint64_t len);
int __libaaa_buffer_write(__libaaa_pg_context_t* ctx, const void* buffer, uint16_t len);
int __libaaa_ats_write(__libaaa_pg_context_t* ctx, const void* buffer, uint16_t len);
int __libaaa_ats_zero(__libaaa_pg_context_t* ctx, uint16_t offset, uint16_t len);
int __libaaa_ats_finish(__libaaa_pg_context_t* ctx);

//
// === Alias functions (macros) ===
//
#ifdef __LIBAAA_NET_SWAP_BYTES
#define __libaaa_hton(in, out, len) __libaaa_byte_swap(in, out, len)
#define __libaaa_ntoh(in, out, len) __libaaa_byte_swap(in, out, len)
#else
#define __libaaa_hton(in, out, len) memcpy(out, in, len)
#define __libaaa_ntoh(in, out, len) memcpy(out, in, len)
#endif

//
// === Internal function implementations ===
//
void __libaaa_byte_swap(const char* in, char* out, uint64_t len)
{
    for (uint64_t i = 0; i < len; ++i)
    {
        out[i] = in[len - 1 - i];
    }
}
int __libaaa_buffer_write(__libaaa_pg_context_t* ctx, const void* buffer, uint16_t len)
{
    if (len <= ctx->buffer_size - ctx->buffer_head)
    {
        memcpy(&ctx->buffer[ctx->buffer_head], buffer, len);
        ctx->buffer_head += len;
        return LIBAAA_OK;
    }
    return LIBAAA_ERROR;
}
int __libaaa_ats_write(__libaaa_pg_context_t* ctx, const void* buffer, uint16_t len)
{
    if (ctx->ats_type != __LIBAAA_CTX_ATS_LONG_EXTENDED)
    {
        // Handle normal writes
        if (len <= ctx->ats_capacity)
        {
            memcpy(&ctx->buffer[ctx->buffer_head], buffer, len);
            ctx->buffer_head += len;
            ctx->ats_capacity -= len;
            return LIBAAA_OK;
        }
    }
    else
    {
        // Handle long extended writes
        uint16_t write_len = len < ctx->ats_capacity ? len : ctx->ats_capacity;
        memcpy(&ctx->buffer[ctx->buffer_head], buffer, write_len);
        ctx->buffer_head += write_len;
        ctx->ats_capacity -= write_len;

        // Handle longer writes
        if (write_len < len)
        {
            uint16_t new_len = len - write_len;
            const void* new_buffer = &((char*)buffer)[write_len];

            // Set more flag
            ctx->buffer[ctx->ats_base + __LIBAAA_PO_ATTRIBUTE_LONG_EXT_EXT_TYPE_FLAGS] = 0b10000000u;

            if (libaaa_pg_attribute_begin_long_extended(ctx, ctx->buffer[ctx->ats_base + __LIBAAA_PO_ATTRIBUTE_LONG_EXT_TYPE], ctx->buffer[ctx->ats_base + __LIBAAA_PO_ATTRIBUTE_LONG_EXT_EXT_TYPE]) == LIBAAA_OK)
            {
                return __libaaa_ats_write(ctx, new_buffer, new_len);
            }
        }
        return LIBAAA_OK;
    }
    return LIBAAA_ERROR;
}
int __libaaa_ats_zero(__libaaa_pg_context_t* ctx, uint16_t offset, uint16_t len)
{
    if (len <= ctx->ats_capacity - offset)
    {
        memset(&ctx->buffer[ctx->buffer_head + offset], 0x0, len);
        return LIBAAA_OK;
    }
    return LIBAAA_ERROR;
}
int __libaaa_ats_finish(__libaaa_pg_context_t* ctx)
{
    if (ctx->ats_type != __LIBAAA_CTX_ATS_NONE)
    {
        uint16_t length = ctx->buffer_head - ctx->ats_base;
        ctx->buffer[ctx->ats_base + __LIBAAA_PO_ATTRIBUTE_EXT_LENGTH] = length;
        ctx->ats_capacity = 0;
        ctx->ats_base = 0;
        ctx->ats_type = __LIBAAA_CTX_ATS_NONE;
    }
    return LIBAAA_OK;
}

//
// === Public function implementations
//
LIBAAA_API int libaaa_pg_init(libaaa_pg_context_t context, void* output_buffer, int output_buffer_size)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;
    
    // Validate buffer size 
    // We don't validate the code of the packet during creation. 
    if (output_buffer_size >= 20 && output_buffer_size <= 4096)
    {
        // Set buffer params
        ctx->buffer = (uint8_t*)output_buffer;
        ctx->buffer_size = output_buffer_size;
        ctx->ats_type = __LIBAAA_CTX_ATS_NONE;
        ctx->ats_base = 0;
        ctx->ats_capacity = 0;

        return LIBAAA_OK;
    }
    return LIBAAA_ERROR;
}

LIBAAA_API void libaaa_pg_reset(libaaa_pg_context_t context, libaaa_radius_code_t code, uint8_t identifier)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;

    // We pretend the header has been written
    ctx->buffer_head = __LIBAAA_PO_HEADER_FIRST_ATTRIBUTE;

    // Now we write the first header values (that we already know)
    ctx->buffer[__LIBAAA_PO_HEADER_CODE] = code;
    ctx->buffer[__LIBAAA_PO_HEADER_IDENTIFIER] = identifier;
    
    // Clear the authenticator for security reasons
    memset(&ctx->buffer[__LIBAAA_PO_HEADER_AUTHENTICATOR], 0x0, 16); 
    
    // Reset attribute state
    ctx->ats_type = __LIBAAA_CTX_ATS_NONE;
}


LIBAAA_API int libaaa_pg_finalize(libaaa_pg_context_t context)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;

    // Finalize ats
    __libaaa_ats_finish(ctx);

    // Write packet length and return it
    __libaaa_hton(&ctx->buffer_head, &ctx->buffer[__LIBAAA_PO_HEADER_LENGTH], 2);
    return ctx->buffer_head;
}

LIBAAA_API void libaaa_pg_set_authenticator(libaaa_pg_context_t context, const void* authenticator)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;
    memcpy(&ctx->buffer[__LIBAAA_PO_HEADER_AUTHENTICATOR], authenticator, 16);
}

LIBAAA_API int libaaa_pg_attribute_begin(libaaa_pg_context_t context, libaaa_radius_attribute_type_t type)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;

    __libaaa_ats_finish(ctx);

    uint8_t stage[2] = { type, 0x00 };
    if (__libaaa_buffer_write(ctx, stage, 2) == LIBAAA_OK)
    {
        ctx->ats_type = __LIBAAA_CTX_ATS_NORMAL;
        ctx->ats_base = ctx->buffer_head - 2;
        ctx->ats_capacity = 255 - 2;

        // Adjust based on general capacity
        if (ctx->ats_capacity > ctx->buffer_size - ctx->buffer_head)
        {
            ctx->ats_capacity = ctx->buffer_size - ctx->buffer_head;
        }

        return LIBAAA_OK;
    }
    return LIBAAA_ERROR;
}

LIBAAA_API int libaaa_pg_attribute_begin_extended(libaaa_pg_context_t context, libaaa_radius_attribute_type_t type, libaaa_radius_attribute_type_t extended_type)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;

    __libaaa_ats_finish(ctx);

    uint8_t stage[3] = { type, 0x00, extended_type };
    if (__libaaa_buffer_write(ctx, stage, 3) == LIBAAA_OK)
    {
        ctx->ats_type = __LIBAAA_CTX_ATS_EXTENDED;
        ctx->ats_base = ctx->buffer_head - 3;
        ctx->ats_capacity = 255 - 3;

        // Adjust based on general capacity
        if (ctx->ats_capacity > ctx->buffer_size - ctx->buffer_head)
        {
            ctx->ats_capacity = ctx->buffer_size - ctx->buffer_head;
        }

        return LIBAAA_OK;
    }
    return LIBAAA_ERROR;
}

LIBAAA_API int libaaa_pg_attribute_begin_long_extended(libaaa_pg_context_t context, libaaa_radius_attribute_type_t type, libaaa_radius_attribute_type_t extended_type)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;

    __libaaa_ats_finish(ctx);

    uint8_t stage[4] = { type, 0x00, extended_type, 0x00 };
    if (__libaaa_buffer_write(ctx, stage, 4) == LIBAAA_OK)
    {
        ctx->ats_type = __LIBAAA_CTX_ATS_LONG_EXTENDED;
        ctx->ats_base = ctx->buffer_head - 4;
        ctx->ats_capacity = 255 - 4;

        // Adjust based on general capacity
        if (ctx->ats_capacity > ctx->buffer_size - ctx->buffer_head)
        {
            ctx->ats_capacity = ctx->buffer_size - ctx->buffer_head;
        }

        return LIBAAA_OK;
    }
    return LIBAAA_ERROR;
}

LIBAAA_API int libaaa_pg_attribute_begin_vendor_specific(libaaa_pg_context_t context, libaaa_vendor_id_t vendor_id)
{
    if(libaaa_pg_attribute_begin(context, 26) == LIBAAA_OK)
    {
        return libaaa_pg_write_integer(context, vendor_id);
    }
    return LIBAAA_ERROR;
}

LIBAAA_API int libaaa_pg_attribute_begin_extended_vendor_specific(libaaa_pg_context_t context, libaaa_radius_attribute_type_t type, libaaa_vendor_id_t vendor_id, libaaa_radius_attribute_type_t vendor_type)
{
    // Begin
    if (type >= LIBAAA_RADIUS_ATTRIBUTE_TYPE_EXTENDED_VENDOR_SPECIFIC_1 && type <= LIBAAA_RADIUS_ATTRIBUTE_TYPE_EXTENDED_VENDOR_SPECIFIC_4)
    {
        if (libaaa_pg_attribute_begin_extended(context, type, 26) == LIBAAA_ERROR)
        {
            return LIBAAA_ERROR;
        }
    }
    else if (type >= LIBAAA_RADIUS_ATTRIBUTE_TYPE_EXTENDED_VENDOR_SPECIFIC_5 && type <= LIBAAA_RADIUS_ATTRIBUTE_TYPE_EXTENDED_VENDOR_SPECIFIC_6)
    {
        if (libaaa_pg_attribute_begin_long_extended(context, type, 26) == LIBAAA_ERROR)
        {
            return LIBAAA_ERROR;
        }
    }
    else
    {
        return LIBAAA_ERROR;
    }

    // Write vendor details
    if (libaaa_pg_write_integer(context, vendor_id) == LIBAAA_OK)
    {
        return libaaa_pg_write_string(context, &vendor_type, 1);
    }
    return LIBAAA_ERROR;
}

LIBAAA_API int libaaa_pg_write_integer(libaaa_pg_context_t context, uint32_t value)
{
    uint32_t swap;
    __libaaa_hton(&value, &swap, sizeof(uint32_t));
    return __libaaa_ats_write(context, &swap, sizeof(uint32_t));
}

LIBAAA_API int libaaa_pg_write_time(libaaa_pg_context_t context, time_t value)
{
    return libaaa_pg_write_integer(context, (uint32_t)value);
}

LIBAAA_API int libaaa_pg_write_text(libaaa_pg_context_t context, const char* value, int len)
{
    return __libaaa_ats_write(context, value, len);
}

LIBAAA_API int libaaa_pg_write_string(libaaa_pg_context_t context, const void* value, int len)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;

    if (ctx->ats_type == __LIBAAA_CTX_ATS_LONG_EXTENDED)
    {
        return __libaaa_ats_write(ctx, value, len);
    }
    else
    {
        // Evaluate how many bytes can be written
        int write_len = len > ctx->ats_capacity ? ctx->ats_capacity : len;

        // Write current set (we don't need to check the return value!
        __libaaa_ats_write(ctx, value, write_len);

        // Write next set
        if (write_len < len)
        {
            int new_len = len - write_len;
            const void* new_value = &((const char*)value)[write_len];

            // Begin new packet
            int status_code = LIBAAA_ERROR;
            switch (ctx->ats_type)
            {
                case __LIBAAA_CTX_ATS_NORMAL:
                    status_code = libaaa_pg_attribute_begin(context, ctx->buffer[ctx->ats_base + __LIBAAA_PO_ATTRIBUTE_TYPE]);
                    break;
                case __LIBAAA_CTX_ATS_EXTENDED:
                    status_code = libaaa_pg_attribute_begin_extended(context, ctx->buffer[ctx->ats_base + __LIBAAA_PO_ATTRIBUTE_EXT_TYPE], ctx->buffer[ctx->ats_base + __LIBAAA_PO_ATTRIBUTE_EXT_EXT_TYPE]);
                    break;
            };

            // Evaluate code
            if (status_code != LIBAAA_OK)
            {
                return LIBAAA_ERROR;
            }

            return libaaa_pg_write_string(context, new_value, new_len);
        }
        return LIBAAA_OK;
    }
    return LIBAAA_ERROR;
}

LIBAAA_API int libaaa_pg_write_ifid(libaaa_pg_context_t context, libaaa_ifid_t ifid)
{
    return __libaaa_ats_write(context, ifid, sizeof(libaaa_ifid_t));
}

LIBAAA_API int libaaa_pg_write_ipv4addr(libaaa_pg_context_t context, libaaa_ipv4addr_t ipv4)
{
    return __libaaa_ats_write(context, ipv4, sizeof(libaaa_ipv4addr_t));
}

LIBAAA_API int libaaa_pg_write_ipv6addr(libaaa_pg_context_t context, libaaa_ipv6addr_t ipv6)
{
    return __libaaa_ats_write(context, ipv6, sizeof(libaaa_ipv6addr_t));
}

LIBAAA_API int libaaa_pg_write_ipv6prefix(libaaa_pg_context_t context, uint8_t prefix_len, libaaa_ipv6addr_t prefix)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;

    if (prefix_len <= 128)
    {
        uint8_t header[2] = { 0, prefix_len };
        if (__libaaa_ats_write(context, header, 2) == LIBAAA_OK)
        {
            uint8_t prefix_write_len = (prefix_len + 7) / 8;
            if (__libaaa_ats_zero(context, prefix_write_len - 1, 1) == LIBAAA_OK)
            {
                if(__libaaa_ats_write(context, prefix, prefix_write_len) == LIBAAA_OK)
                {
                    ctx->buffer[ctx->buffer_head - 1] &= 0b11111111 << prefix_len % 8;
                    return LIBAAA_OK;
                }
            }
        }
    }
    return LIBAAA_ERROR;
}

LIBAAA_API int libaaa_pg_write_ipv4prefix(libaaa_pg_context_t context, uint8_t prefix_len, libaaa_ipv4addr_t prefix)
{
    __libaaa_pg_context_t* ctx = (__libaaa_pg_context_t*)context;

    if (prefix_len <= 32)
    {
        uint8_t header[2] = { 0, prefix_len };
        if (__libaaa_ats_write(context, header, 2) == LIBAAA_OK)
        {
            uint8_t prefix_write_len = (prefix_len + 7) / 8;
            if (__libaaa_ats_zero(context, prefix_write_len - 1, 1) == LIBAAA_OK)
            {
                if(__libaaa_ats_write(context, prefix, prefix_write_len) == LIBAAA_OK)
                {
                    ctx->buffer[ctx->buffer_head - 1] &= 0b11111111 << prefix_len % 8;
                    return LIBAAA_OK;
                }
            }
        }
    }
    return LIBAAA_ERROR;
}

LIBAAA_API int libaaa_pg_write_integer64(libaaa_pg_context_t context, uint64_t value)
{
    uint64_t swap;
    __libaaa_hton(&value, &swap, sizeof(uint64_t));
    return __libaaa_ats_write(context, &swap, sizeof(uint64_t));
}