from __future__ import print_function

from .secp256k1 import hashsn, sbmul, hashpn, submodn, mulmodn
from .utils import hashs


def _hash_points_and_message(a, b, m): return hashsn(hashpn(a, b), m)


def schnorr_create(secret, message, point=None):
    assert isinstance(secret, int)
    assert isinstance(message, int)
    xG = point * secret if point else sbmul(secret)
    print(xG)
    k = hashsn(message, secret)
    kG = point * k if point else sbmul(k)
    e = hashs(xG.x, xG.y, kG.x, kG.y, message)
    s = submodn(k, mulmodn(secret, e))
    return xG, s, e, message


def schnorr_calc(xG, s, e, message, point=None):
    assert isinstance(s, int)
    assert isinstance(e, int)
    assert isinstance(message, int)
    sG = point * s if point else sbmul(s)
    kG = sG + (xG * e)
    return hashs(xG.x, xG.y, kG.x, kG.y, message)


def schnorr_verify(xG, s, e, message, point=None):
    return e == schnorr_calc(xG, s, e, message, point)


if __name__ == "__main__":
    s = 19977808579986318922850133509558564821349392755821541651519240729619349670944
    m = 19996069338995852671689530047675557654938145690856663988250996769054266469975
    proof = schnorr_create(s, m)
    assert proof[1] == 9937528682437333073292374920792423444152291976168124823244260606973530841357
    assert proof[2] == 62556699762868942562895201798238094653401696340984411017785245503967199042244
    print(schnorr_verify(*proof))
