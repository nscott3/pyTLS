import sys
import binascii
import math
from functools import reduce
from os import urandom
from Cryptodome.Hash import SHA3_256


def quote(x): return '"' + str(x) + '"'


quotemany = lambda *x: ','.join(map(quote, x))
def quotelist(x): return '[' + quotemany(*x) + ']'


safe_ord = ord if sys.version_info.major == 2 else lambda x: x if isinstance(
    x, int) else ord(x)


def bytes_to_int(x): return reduce(
    lambda o, b: (o << 8) + safe_ord(b), [0] + list(x))


def bytes_to_ints(bytes_chunk):
    return [bytes_to_int(b) for b in [bytes_chunk[i:i+32] for i in range(0, len(bytes_chunk), 32)]]


def packl(lnum):
    if lnum == 0:
        return b'\0'
    s = hex(lnum)[2:].rstrip('L')
    if len(s) & 1:
        s = '0' + s
    return binascii.unhexlify(s)


int_to_big_endian = packl


def zpad(x, l): return b'\x00' * max(0, l - len(x)) + x


def tobe256(v): return zpad(int_to_big_endian(v), 32)


def hashs(*x):
    data = b''.join(map(tobe256, x))
    # return bytes_to_int(keccak_256(data).digest())
    return bytes_to_int(SHA3_256.new(data).digest())


def randb256(): return urandom(32)


def bit_clear(n, b): return n ^ (1 << (b-1)) if n & 1 << (b-1) else n


def bit_set(n, b): return n | (1 << (b-1))


def bit_test(n, b): return 0 != (n & (1 << (b-1)))


def powmod(a, b, n):
    c = 0
    f = 1
    k = int(math.log(b, 2))
    while k >= 0:
        c *= 2
        f = (f*f) % n
        if b & (1 << k):
            c += 1
            f = (f*a) % n
        k -= 1
    return f


def decode_pem(data):
    data = ''.join(data.split('\n')[4:-2])
    data = binascii.a2b_base64(data)
    return bytes_to_int(data)


def int_to_32_bytes(n):
    return n.to_bytes(32, byteorder='big')


# def bytes_to_int(b):
#     return int.from_bytes(b, byteorder='big')


if __name__ == "__main__":
    # assert bin(bit_clear(3, 1)) == '0b10'
    # assert bin(bit_clear(3, 2)) == '0b1'
    # assert bin(bit_set(0, 1)) == '0b1'
    max_256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    print(max_256-n)
    print(bin(432420386565659656852420866394968145598))
    # convert to bits
    print(bin(n))
