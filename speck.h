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

#ifndef SPECK_H
#define SPECK_H

#include <stdint.h>

typedef __int128           int128_t;
typedef unsigned __int128 uint128_t;

#define RR64(x, r)     ((x >> r) | (x << (64 - r)))
#define RL64(x, r)     ((x << r) | (x >> (64 - r)))
#define ROUND(x, y, k)  (x = RR64(x, 8), x += y, x ^= k, y = RL64(y, 3), y ^= x)
#define RROUND(x, y, k) (y ^= x, y = RR64(y, 3), x ^= k, x -= y, x = RL64(x, 8))

// A simple struct to store the key schedule.
struct _key_sch_t {
    uint64_t k[32];
};
typedef struct _key_sch_t key_sch_t;
/**
 *speck_encrypt - Speck 128/128 block encryption.
 * ks: The key schedule to encrypt with.
 * pt: The plain text block.
 * Returns: The encrypted block.
 */
uint128_t   speck_encrypt(const key_sch_t ks, const uint128_t pt);
/**
 *speck_encrypt - Speck 128/128 block decryption.
 * ks: The key schedule to decrypt with.
 * ct: The cipher text block.
 * Returns: The plain text block.
 */
uint128_t   speck_decrypt     (const key_sch_t ks, const uint128_t ct);
/**
 * speck_key_schedule - Speck 128/128 key schedule generation.
 * Returns: The struct key_sch_t. This is used with the decrypt and encrypt
 *          functions.
 */
key_sch_t   speck_key_schedule(const uint128_t key);
/**
 * speck_cbc_encrypt - Speck 128/128 CBC encryption
 * ks   : The key schedule.
 * iv   : Initialization vector.
 * data : Data to encrypt in place.
 * len  : Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on bad length.
 */
int speck_CBC_encrypt(const key_sch_t ks, const uint128_t iv, uint8_t* data, uint64_t len);
/**
 * speck_cbc_decrypt - Speck 128/128 CBC encryption
 * ks   : The key schedule.
 * iv   : Initialization vector.
 * data : Data to decrypt in place.
 * len  : Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on bad length.
 */
int speck_CBC_decrypt(const key_sch_t ks, const uint128_t iv, uint8_t* data, uint64_t len);

#endif