import struct
import binascii


def circ_left_shift(word, n):
    return ((word << n) & 0xffffffff) | (word >> (32 - n))


def circ_right_shift(word, n):
    return ((word >> n) & 0xffffffff) | (word << (32 - n))


def ch(a, b, c):
    return ((a & (b ^ c)) ^ c)


def maj(a, b, c):
    return ((a & (b | c)) | (b & c))


def bsig0(word):
    return circ_right_shift(word, 2) ^ circ_right_shift(word, 13) ^ circ_right_shift(word, 22)


def bsig1(word):
    return circ_right_shift(word, 6) ^ circ_right_shift(word, 11) ^ circ_right_shift(word, 25)


def ssig0(word):
    return circ_right_shift(word, 7) ^ circ_right_shift(word, 18) ^ (word >> 3)


def ssig1(word):
    return circ_right_shift(word, 17) ^ circ_right_shift(word, 19) ^ (word >> 10)


def u64_circ_left_shift(word, n):
    return ((word << n) & 0xffffffffffffffff) | (word >> (64 - n))


def u64_circ_right_shift(word, n):
    return ((word >> n) & 0xffffffffffffffff) | (word << (64 - n))


def u64_bsig0(word):
    return u64_circ_right_shift(word, 28) ^ u64_circ_right_shift(word, 34) ^ u64_circ_right_shift(word, 39)


def u64_bsig1(word):
    return u64_circ_right_shift(word, 14) ^ u64_circ_right_shift(word, 18) ^ u64_circ_right_shift(word, 41)


def u64_ssig0(word):
    return u64_circ_right_shift(word, 1) ^ u64_circ_right_shift(word, 8) ^ (word >> 7)


def u64_ssig1(word):
    return u64_circ_right_shift(word, 19) ^ u64_circ_right_shift(word, 61) ^ (word >> 6)


def sha1(string: bytes) -> bytes:
    string += \
        b'\x80' + \
        b'\x00' * (-(len(string) + 1 + 8) % 64) + \
        struct.pack('>Q', len(string)*8)

    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476
    h4 = 0xc3d2e1f0

    for chunk_start in range(0, len(string), 64):
        w = []

        for i in range(16):
            w.append(struct.unpack('>I', string[chunk_start:chunk_start+4])[0])
            chunk_start += 4

        for i in range(16, 80):
            w.append(circ_left_shift(w[-3] ^ w[-8] ^ w[-14] ^ w[-16], 1))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if i < 20:
                f = d ^ (b & (c ^ d))
                k = 0x5a827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif i < 60:
                f = (b & (c | d)) | (c & d)
                k = 0x8f1bbcdc
            else:
                f = b ^ c ^ d
                k = 0xca62c1d6

            temp = (circ_left_shift(a, 5) + f + e + k + w[i]) & 0xffffffff
            e = d
            d = c
            c = circ_left_shift(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return struct.pack(">IIIII", h0, h1, h2, h3, h4)


def sha1_hex(string: bytes) -> bytes:
    return binascii.b2a_hex(sha1(string))


def hmac_sha1(key: bytes, text: bytes) -> bytes:
    if len(key) > 64:
        key = sha1(key)
    key += b'\x00' * (64 - len(key))

    ipad = bytearray(key)
    opad = bytearray(key)

    for i in range(64):
        ipad[i] ^= 0x36
        opad[i] ^= 0x5C

    return sha1(opad + sha1(ipad + text))


def hmac_sha1_hex(key: bytes, text: bytes) -> bytes:
    return binascii.b2a_hex(hmac_sha1(key, text))


sha256constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def sha256(string: bytes) -> bytes:
    string += \
        b'\x80' + \
        b'\x00' * (-(len(string) + 1 + 8) % 64) + \
        struct.pack('>Q', len(string)*8)

    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    for chunk_start in range(0, len(string), 64):
        w = []

        for i in range(16):
            w.append(struct.unpack(">I", string[chunk_start:chunk_start+4])[0])
            chunk_start += 4

        for i in range(16, 64):
            w.append((ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16]) & 0xffffffff)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        for i in range(64):
            t1 = (h + bsig1(e) + ch(e, f, g) + sha256constants[i] + w[i]) & 0xffffffff
            t2 = (bsig0(a) + maj(a, b, c)) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff

    return struct.pack(">IIIIIIII", h0, h1, h2, h3, h4, h5, h6, h7)


def sha256_hex(string: bytes) -> bytes:
    return binascii.b2a_hex(sha256(string))


def hmac_sha256(key: bytes, text: bytes) -> bytes:
    if len(key) > 64:
        key = sha256(key)
    key += b'\x00' * (64 - len(key))

    ipad = bytearray(key)
    opad = bytearray(key)

    for i in range(64):
        ipad[i] ^= 0x36
        opad[i] ^= 0x5C

    return sha256(opad + sha256(ipad + text))


def hmac_sha256_hex(key: bytes, text: bytes) -> bytes:
    return binascii.b2a_hex(hmac_sha256(key, text))


sha512constants = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]


def sha512(string: bytes) -> bytes:
    string += \
        b'\x80' + \
        b'\x00' * (-(len(string) + 1 + 8) % 128) + \
        struct.pack('>Q', len(string)*8)

    h0 = 0x6a09e667f3bcc908
    h1 = 0xbb67ae8584caa73b
    h2 = 0x3c6ef372fe94f82b
    h3 = 0xa54ff53a5f1d36f1
    h4 = 0x510e527fade682d1
    h5 = 0x9b05688c2b3e6c1f
    h6 = 0x1f83d9abfb41bd6b
    h7 = 0x5be0cd19137e2179

    u64_li = 0xffffffffffffffff

    for chunk_start in range(0, len(string), 128):
        w = []

        for i in range(16):
            w.append(struct.unpack(">Q", string[chunk_start:chunk_start+8])[0])
            chunk_start += 8

        for i in range(16, 80):
            w.append((u64_ssig1(w[i-2]) + w[i-7] + u64_ssig0(w[i-15]) + w[i-16]) & u64_li)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        for i in range(80):
            t1 = (h + u64_bsig1(e) + ch(e, f, g) + sha512constants[i] + w[i]) & u64_li
            t2 = (u64_bsig0(a) + maj(a, b, c)) & u64_li
            h = g
            g = f
            f = e
            e = (d + t1) & u64_li
            d = c
            c = b
            b = a
            a = (t1 + t2) & u64_li

        h0 = (h0 + a) & u64_li
        h1 = (h1 + b) & u64_li
        h2 = (h2 + c) & u64_li
        h3 = (h3 + d) & u64_li
        h4 = (h4 + e) & u64_li
        h5 = (h5 + f) & u64_li
        h6 = (h6 + g) & u64_li
        h7 = (h7 + h) & u64_li

    return struct.pack(">QQQQQQQQ", h0, h1, h2, h3, h4, h5, h6, h7)


def sha512_hex(string: bytes) -> bytes:
    return binascii.b2a_hex(sha512(string))


def hmac_sha512(key: bytes, text: bytes) -> bytes:
    if len(key) > 128:
        key = sha512(key)
    key += b'\x00' * (128 - len(key))

    ipad = bytearray(key)
    opad = bytearray(key)

    for i in range(128):
        ipad[i] ^= 0x36
        opad[i] ^= 0x5C

    return sha512(opad + sha512(ipad + text))


def hmac_sha512_hex(key: bytes, text: bytes) -> bytes:
    return binascii.b2a_hex(hmac_sha512(key, text))

# print(binascii.b2a_hex(hmac_sha512(b'the bee movie', b"""According to all known laws
# of aviation,
# there is no way a bee
# should be able to fly.
# Its wings are too small to get
# its fat little body off the ground.
# The bee, of course, flies anyway
# because bees don't care
# what humans think is impossible.
# Yellow, black. Yellow, black.
# Yellow, black. Yellow, black.
# Ooh, black and yellow!
# Let's shake it up a little.
# Barry! Breakfast is ready!
# Ooming!
# Hang on a second.
# Hello?
# - Barry?
# - Adam?
# - Oan you believe this is happening?
# - I can't. I'll pick you up.
# Looking sharp.
# Use the stairs. Your father
# paid good money for those.
# Sorry. I'm excited.
# Here's the graduate.
# We're very proud of you, son.
# A perfect report card, all B's.
# Very proud.
# Ma! I got a thing going here.
# - You got lint on your fuzz.
# - Ow! That's me!
# - Wave to us! We'll be in row 118,000.
# - Bye!
# Barry, I told you,
# stop flying in the house!
# - Hey, Adam.
# - Hey, Barry.
# - Is that fuzz gel?
# - A little. Special day, graduation.""")))

# incorrect: 1f5a2a39a892a8c4959a45604bcf9d2caef482e0cf3df046fbbf4b9cc12973d090306ee5b306e5e2ec1fa49e63e38d514dda54bee3c8812d7fe371f66ccbca98
# correct:   78553549e63a1ad55ff0af86d3c23c7e5e8b6146d09fab87009ec769a3ff8fce

#print(hmac_hex(b"A quick fox ", b"jumps over a lazy frog"))
# print(hmac_hex(b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ', b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim '))
# print(sha1_hex(b"A quick fox jumps over a lazy frog"))
# print(sha1_hex(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim "))
# 10e7dbc4e21a0195ee536850dcafbfece9b73f24

# incorrect: 6666�Jp/6666���6666�S�6666h+am6666D��666666666666666666666666
# correct:   6666 Jp/6666   6666 S 6666h+am6666D  666666666666666666666666