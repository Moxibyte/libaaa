# Welcome to LibAAA

!!! info
    Dear visitor. Thank you for visiting libaaa.cc!

    We are currently in the process of developing LibAAA. During the development of the lib, bindings and reference implementation all content is subject to change. So please keep in mind that everything might change until we release our first official version. However we would really appreciate when you already use our lib and give us feedback. 

    This documentation will always reflect the latest version of the lib / the working draft.

    All Features stated on this page are currently planed or might be partially implemented. See the disclaimer in our license!

### Description
LibAAA is a plain C99 implementation of the radius protocol (RFC 2865, RFC 2868, RFC 6929, RFC 8044, RFC 5080). We provide a packet generator and a validating packet reader (SAX style). LibAAA is cross-platform and only uses a minimal subset of features (`stdint.h`, `memcpy()` and `memset()`). The library performs no memory allocation.

The library also provides a header only C++ wrapper out of the box. The C++ implementation allows packet creation and reading the C++ style (`packet << Attribute(...)`, `value = packet[Attribute]`, ...).

We also provide an optional server and client reference implementation written in C++. This implementation is modular and it's default facades build ontop of ASIO (UDP/IP) and botan (Crypto).

### How to obtain LibAAA
LibAAA will be available as conan packages from conan-index or can be build manually using CMake. We plan to provide the following conan packages:

- **LibAAA** Core C99 lib with C++ header.
- **LibAAA-Server** C++ Server reference implementation (with ASIO and botan facade)
- **LibAAA-Client** C++ Client reference implementation (with ASIO and botan facade)
