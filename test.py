#!/usr/bin/env python
# coding=utf-8

buf = [0x61, 0x41, 0x22, 0x1, 0x2, 0x1, 0x2, 0x1]
out = range(len(buf))
prev1 = 0
prev2 = 0
prev3 = 0

for i in range(len(buf)):
    out[i] = (buf[i] + ((0x55555556 * (prev2 + prev1 + prev3)) >> 32) - ((prev2 + prev1 + prev3) >> 31)) & 0xff
    prev1, prev2, prev3 = prev2, prev3, out[i]

print ''.join(map(chr, out))


