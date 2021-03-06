/*
MIT License

Copyright (c) 2017 Keith J. Cancel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include "speck.h"

int main() {
    const char *msgs[] = {
        "FAILED!",
        "Success."
    };
    uint128_t key = ((uint128_t)0x0f0e0d0c0b0a0908 << 64) | 0x0706050403020100;
    uint128_t pt  = ((uint128_t)0x6c61766975716520 << 64) | 0x7469206564616d20;
    uint128_t ct  = ((uint128_t)0xa65d985179783265 << 64) | 0x7860fedf5c570d18;
    key_sch_t sch = speck_key_schedule(key);
    // Encrypt
    uint128_t out = speck_encrypt(sch, pt);
    printf("Block Encryption: %s\n", msgs[(out == ct)]);
    // Decrypt
    out = speck_decrypt(sch, out);
    printf("Block Decryption: %s\n", msgs[(out == pt)]);
    
    // Test CBC
    uint128_t ct_blks[3] = {
        ((uint128_t)0x6af7667c1bc448b1 << 64 | 0x607123d87d150011),
        ((uint128_t)0xa8ef28dfc242148e << 64 | 0x4dc09cf8af2a139b),
        ((uint128_t)0x163674b381ede62d << 64 | 0x27c68acc729b5562)
    };
    uint8_t   str[] = "The Quick Brown fox jumped over the lazy dog!   ";
    uint128_t iv    = ((uint128_t)0xc8f3aa564259d93f << 64) | 0x588bc260826333d2;
    uint128_t *blks = (uint128_t *)str;
    speck_CBC_encrypt(sch, iv, str, 48);
    int failed = 0;
    for(int i = 0; i < 3; i++) {
        failed = (ct_blks[i] != blks[i]);
    }
    printf("CBC   Encryption: %s\n", msgs[!failed]);
    /*printf(
        "\nCBC Encrypt:\n%016llx %016llx %016llx\n%016llx %016llx %016llx\n",
        (uint64_t)(blks[0] >> 64),
        (uint64_t)(blks[0]),
        (uint64_t)(blks[1] >> 64),
        (uint64_t)(blks[1]),
        (uint64_t)(blks[2] >> 64),
        (uint64_t)(blks[2])
    );*/
    speck_CBC_decrypt(sch, iv, str, 48);
    failed = (memcmp(
        str,
        "The Quick Brown fox jumped over the lazy dog!   ",
        49
    ) != 0);
    printf("CBC   Decryption: %s\n", msgs[!failed]);
    return 0;
}