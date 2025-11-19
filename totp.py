import struct
import time
# import buildinsha as sha
import sha
import math
import base64


def generate_totp(secret: bytes, timeorigin=0, timestep=30, length=6, algorithm='SHA1'):
    match algorithm:
        case 'SHA1':
            arr = sha.hmac_sha1(
                secret, struct.pack(">Q", math.floor((time.time() - timeorigin) / timestep)))
        case 'SHA256':
            arr = sha.hmac_sha256(
                secret, struct.pack(">Q", math.floor((time.time() - timeorigin) / timestep)))
        case 'SHA512':
            arr = sha.hmac_sha512(
                secret, struct.pack(">Q", math.floor((time.time() - timeorigin) / timestep)))
        case _:
            raise NotImplementedError(f"{algorithm} not supported")
    # grab the offset
    offset = arr[-1] & 0xf
    # grab the dynamic byte code
    p = struct.unpack('>I', arr[offset:offset + 4])[0] & 0x7fffffff
    return p % pow(10, length)


def decode_b32_secret(secret: str):
    # remove any junk the user may get from the service
    bettersecret = secret.replace(' ', '').replace('-', '').upper()
    # pad the secret to a multiple of 8
    return base64.b32decode(bettersecret + '='*(-len(bettersecret) % 8))
