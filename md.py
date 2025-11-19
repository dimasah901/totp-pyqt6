import struct
import binascii
import math


def circ_left_shift(word, n):
    return ((word << n) & 0xffffffff) | (word >> (32 - n))


def circ_right_shift(word, n):
    return ((word >> n) & 0xffffffff) | (word << (32 - n))


def aux_f(x, y, z):
    return x & y | (0xffffffff-x) & z


def aux_g(x, y, z):
    return x & z | y & (0xffffffff-z)


def aux_h(x, y, z):
    return x ^ y ^ z


def aux_i(x, y, z):
    return y ^ (x | (0xffffffff-z))


md5_operations = [
    [
        [[0, 7, 1], [4, 7, 5], [8, 7, 9], [12, 7, 13]],
        [[1, 12, 2], [5, 12, 6], [9, 12, 10], [13, 12, 14]],
        [[2, 17, 3], [6, 17, 7], [10, 17, 11], [14, 17, 15]],
        [[3, 22, 4], [7, 22, 8], [11, 22, 12], [15, 22, 16]]
    ],
    [
        [[1, 5, 17], [5, 5, 21], [9, 5, 25], [13, 5, 29]],
        [[6, 9, 18], [10, 9, 22], [14, 9, 26], [2, 9, 30]],
        [[11, 14, 19], [15, 14, 23], [3, 14, 27], [7, 14, 31]],
        [[0, 20, 20], [4, 20, 24], [8, 20, 28], [12, 20, 32]]
    ],
    [
        [[5, 4, 33], [1, 4, 37], [13, 4, 41], [9, 4, 45]],
        [[8, 11, 34], [4, 11, 38], [0, 11, 42], [12, 11, 46]],
        [[11, 16, 35], [7, 16, 39], [3, 16, 43], [15, 16, 47]],
        [[14, 23, 36], [10, 23, 40], [6, 23, 44], [2, 23, 48]]
    ],
    [
        [[0, 6, 49], [12, 6, 53], [8, 6, 57], [4, 6, 61]],
        [[7, 10, 50], [3, 10, 54], [15, 10, 58], [11, 10, 62]],
        [[14, 15, 51], [10, 15, 55], [6, 15, 59], [2, 15, 63]],
        [[5, 21, 52], [1, 21, 56], [13, 21, 60], [9, 21, 64]]
    ]
]

md5_sine = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]


def md5(string: bytes) -> bytes:
    string += \
        b'\x80' + \
        b'\x00' * (-(len(string) + 1 + 8) % 64) + \
        struct.pack('<Q', len(string)*8)

    a = 0x01234567
    b = 0x89abcdef
    c = 0xfedcba98
    d = 0x76543210

    for chunk_start in range(0, len(string), 64):
        w = []

        for i in range(16):
            w.append(struct.unpack('<I', string[chunk_start:chunk_start+4])[0])
            chunk_start += 4

        aa = a
        bb = b
        cc = c
        dd = d

        for r, rf in enumerate([aux_f, aux_g, aux_h, aux_i]):
            for i in range(4):
                a = b + circ_left_shift((a + rf(b, c, d) + w[md5_operations[r][0][i][0]] + md5_sine[md5_operations[r][0][i][2]-1]) & 0xffffffff, md5_operations[r][0][i][1])
            for i in range(4):
                d = a + circ_left_shift((d + rf(a, b, c) + w[md5_operations[r][1][i][0]] + md5_sine[md5_operations[r][1][i][2]-1]) & 0xffffffff, md5_operations[r][1][i][1])
            for i in range(4):
                c = d + circ_left_shift((c + rf(d, a, b) + w[md5_operations[r][2][i][0]] + md5_sine[md5_operations[r][2][i][2]-1]) & 0xffffffff, md5_operations[r][2][i][1])
            for i in range(4):
                b = c + circ_left_shift((b + rf(c, d, a) + w[md5_operations[r][3][i][0]] + md5_sine[md5_operations[r][3][i][2]-1]) & 0xffffffff, md5_operations[r][3][i][1])

        a = (a + aa) & 0xffffffff
        b = (b + bb) & 0xffffffff
        c = (c + cc) & 0xffffffff
        d = (d + dd) & 0xffffffff

    return struct.pack("<IIII", a, b, c, d)


def md5_hex(string: bytes) -> bytes:
    return binascii.b2a_hex(md5(string))
