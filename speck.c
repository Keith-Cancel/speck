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
#include "speck.h"


key_sch_t speck_key_schedule(const uint128_t key) {
    uint64_t k1, k2;
    key_sch_t sch;
    k1 = (uint64_t)(key >> 64);
    k2 = (uint64_t)(key);
    for(int i = 0; i < 32; i++) {
        sch.k[i] = k2;
        ROUND(k1, k2, i);
    }
    return sch;
}

uint128_t speck_decrypt(const key_sch_t ks, const uint128_t ct){
    uint64_t c1, c2;
    c1 = (uint64_t)(ct >> 64);
    c2 = (uint64_t)(ct);
    for(int i = 31; i >= 0; i--) {
        RROUND(c1, c2, ks.k[i]);
    }
    return ((uint128_t)c1 << 64) | c2;
}

uint128_t speck_encrypt(const key_sch_t ks, const uint128_t pt) {
    uint64_t m1, m2;
    m1 = (uint64_t)(pt >> 64);
    m2 = (uint64_t)(pt);
    for(int i = 0; i < 32; i++) {
        ROUND(m1, m2, ks.k[i]);
    }
    return ((uint128_t)m1 << 64) | m2;
}

int speck_CBC_encrypt(const key_sch_t ks, const uint128_t iv, uint8_t* data, uint64_t len) {
    if((len & 0xf) != 0) { // not divisible by 16.
        return -1;
    }
    uint128_t cur_blk;
    uint128_t cur_iv = iv;
    for(uint64_t i = 0; i < len; i += 16) {
        cur_blk = *(uint128_t *)(data+i) ^ cur_iv;
        cur_iv  = speck_encrypt(ks, cur_blk);
        *(uint128_t *)(data+i) = cur_iv;
    }
    return 0;
}

int speck_CBC_decrypt(const key_sch_t ks, const uint128_t iv, uint8_t* data, uint64_t len) {
    if((len & 0xf) != 0) { // not divisible by 16.
        return -1;
    }
    uint128_t cur_blk;
    uint128_t cur_iv = iv;
    for(uint64_t i = 0; i < len; i += 16) {
        cur_blk = *(uint128_t *)(data+i);
        *(uint128_t *)(data+i) = speck_decrypt(ks, cur_blk) ^ cur_iv;
        cur_iv = cur_blk;
    }
    return 0;
}