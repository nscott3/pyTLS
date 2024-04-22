import sys
from random import randint
from functools import reduce
# from py_ecc.secp256k1.secp256k1 import add, multiply, inv, N, P, G, ecdsa_raw_recover
# tinyec
import tinyec.ec as ec
import tinyec.registry as reg
from .utils import hashs, int_to_32_bytes, tobe256, bytes_to_ints
import secrets
# from .ecdsa import pubkey_to_ethaddr

# assert False == "Do not use, use altbn128"

curve = reg.get_curve('secp256k1')
safe_ord = ord if sys.version_info.major == 2 else lambda x: x if isinstance(
    x, int) else ord(x)


def bytes_to_int(x):
    return reduce(lambda o, b: (o << 8) + safe_ord(b), [0] + list(x))


hashsn = lambda *x: hashs(*x) % curve.field.n
hashpn = lambda *x: hashsn(*[item for sublist in x for item in sublist])
def randsn(): return secrets.randbelow(curve.field.n)
def sbmul(s): return s * curve.g
def invmulp(x, y): return (x * pow(y, curve.field.p-2, curve.field.p))
def invmodn(x): return ec.mod_inv(x, curve.field.n)
def addmodn(x, y): return (x + y) % curve.field.n
def mulmodn(x, y): return (x * y) % curve.field.n
def submodn(x, y): return (x - y) % curve.field.n
def negp(x): return (x[0], -x[1])


# def hackymul_raw(x, y, scalar, m=0):
#     """
#     Implements the 'hacky multiply' from:
#     https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384
#     """
#     # m = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#     v = 28 if y % 2 != 0 else 27
#     s = mulmodn(scalar, x)
#     return ecdsa_raw_recover(tobe256(m), (v, x, s))


# def hackymul(x, y, scalar, m=0):
#     return pubkey_to_ethaddr(hackymul_raw(x, y, scalar, m))

def construct_signature(pkeys, tees, cees):
    pkeys_bytes = b''.join([int_to_32_bytes(
        pkey.x) + int_to_32_bytes(pkey.y) for pkey in pkeys])
    tees_bytes = b''.join([int_to_32_bytes(tee) for tee in tees])
    cees_bytes = int_to_32_bytes(cees[-1])

    signature = b''.join([pkeys_bytes, tees_bytes, cees_bytes])
    return signature


def deconstruct_signature(signature):
    cees_bytes, signature = signature[-32:], signature[:-32]

    split_idx = len(signature)*2//3
    pkeys_bytes, tees_bytes = signature[:split_idx], signature[split_idx:]

    pkeys_ints, tees = bytes_to_ints(pkeys_bytes), bytes_to_ints(tees_bytes)
    seed = bytes_to_int(cees_bytes)
    pkeys = [ec.Point(curve, pkeys_ints[i], pkeys_ints[i+1])
             for i in range(0, len(pkeys_ints), 2)]

    return pkeys, tees, seed
