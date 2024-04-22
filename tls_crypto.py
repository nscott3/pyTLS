#!/usr/bin/env python

'''
tls_crypto.py:
Contains various cryptographic functions needed during handshake and record protocols
'''

import hmac
import secrets
from tinyec import registry, ec
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Hash import HMAC, SHA256, SHA384
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.PublicKey import RSA, ECC
from cryptography import x509
from pysolcrypto import aosring
from pysolcrypto.utils import bytes_to_int
import tls_constants


def xor_bytes(bytes_one, bytes_two):
    xor_len = len(bytes_two)
    int_one = int.from_bytes(bytes_one, 'big')
    int_two = int.from_bytes(bytes_two, 'big')
    int_xor = int_one ^ int_two
    return int_xor.to_bytes(xor_len, 'big')


def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


def point_to_secret(pubKey, group):
    secret = pubKey.x.to_bytes(tls_constants.COORD_LEN[group], 'big')
    return secret


def ec_setup(curve_name):
    curve = registry.get_curve(curve_name)
    return curve


def ec_key_gen(curve):
    sec_key = secrets.randbelow(curve.field.n)
    pub_key = sec_key * curve.g
    return (sec_key, pub_key)


def ec_dh(sec_key, pub_key):
    shared_key = sec_key * pub_key
    return shared_key


def convert_ec_pub_bytes(ec_pub_key, group_name):
    x_int = ec_pub_key.x
    y_int = ec_pub_key.y
    x_bytes = x_int.to_bytes(
        tls_constants.COORD_LEN[group_name], byteorder='big')
    y_bytes = y_int.to_bytes(
        tls_constants.COORD_LEN[group_name], byteorder='big')
    return x_bytes + y_bytes


def convert_x_y_bytes_ec_pub(pub_bytes, group_name):
    x_bytes = pub_bytes[:tls_constants.COORD_LEN[group_name]]
    y_bytes = pub_bytes[tls_constants.COORD_LEN[group_name]:]
    x_int = int.from_bytes(x_bytes, byteorder='big')
    y_int = int.from_bytes(y_bytes, byteorder='big')
    curve = ec_setup(tls_constants.GROUP_FLAGS[group_name])
    ec_pub_key = ec.Point(curve, x_int, y_int)
    return ec_pub_key


def get_rsa_pk_from_cert(cert_string):
    public_key = RSA.import_key(cert_string)
    return public_key


def get_ecdsa_pk_from_cert(cert_string):
    public_key = ECC.import_key(cert_string)
    return public_key


def get_ring_pk_from_cert(cert_string):
    public_key = x509.load_pem_x509_certificate(cert_string.encode('utf-8'))
    return public_key.public_key()


class HKDF:
    def __init__(self, csuite):
        self.csuite = csuite
        if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
            hash = SHA256.new()
        if (self.csuite == tls_constants.TLS_AES_256_GCM_SHA384):
            hash = SHA384.new()
        self.hash_length = hash.digest_size

    def tls_hkdf_extract(self, input_key_material, salt):
        if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
            hash = SHA256.new()
        else:
            hash = SHA384.new()
        if (salt == None):
            salt = b'\0' * (self.hash_length)
        if (input_key_material == None):
            input_key_material = b'\0' * (self.hash_length)
        ex_secret = hmac.new(salt, input_key_material, hash).digest()
        return ex_secret

    def tls_hkdf_expand(self, secret, info, length):
        if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
            hash = SHA256.new()
        else:
            hash = SHA384.new()
        ex_secret = hmac.new(secret, info+bytes([1]), hash).digest()
        return ex_secret[:length]


def tls_transcript_hash(csuite, context):
    ##########################
    # THIS IS TO BE ASSESSED
    ##########################
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash = SHA256.new(context)
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash = SHA384.new(context)
    transcript_hash = hash.digest()
    return transcript_hash


'''
def tls_test_transcript_hash(csuite, context):
    ##########################
    # THIS IS TO BE ASSESSED
    ##########################
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash = SHA256.new(context)
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash = SHA384.new(context)
    transcript_hash = hash.digest()
    if (len(context)>8):
        with open('ut_tls_transcript_hash_int_inputs.txt', 'a') as filehandle:
            filehandle.write('\n%d %d\n' % (csuite, len(context)))
        with open('ut_tls_transcript_hash_byte_inputs.txt', 'ab') as filehandle:
            filehandle.write(context)
        with open('ut_tls_transcript_hash_outputs.txt', 'a') as filehandle:
            filehandle.write('\n%s\n' % (transcript_hash.hex()))
    return transcript_hash
'''


def tls_hkdf_label(label, context, length):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    # DOUBLE CHECKED - APPEARS CORRECT
    len_bytes = length.to_bytes(2, 'big')
    lbl_bytes = "tls13".encode() + label
    lbl_len = len(lbl_bytes).to_bytes(1, 'big')
    ctx_bytes = context
    ctx_len = len(ctx_bytes).to_bytes(1, 'big')
    hkdf_lbl = len_bytes + lbl_len + lbl_bytes + ctx_len + ctx_bytes
    return hkdf_lbl


'''
def tls_test_hkdf_label(label, context, length):
    ##########################
    # THIS IS TO BE ASSESSED
    ##########################
    len_bytes = length.to_bytes(2, 'big')
    lbl_bytes = "tls13".encode() + label
    lbl_len = len(lbl_bytes).to_bytes(1, 'big')
    ctx_bytes = context
    ctx_len = len(ctx_bytes).to_bytes(1, 'big')
    hkdf_lbl = len_bytes + lbl_len + lbl_bytes + ctx_len + ctx_bytes
    with open('ut_tls_hkdf_lbl_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %d\n' % (length, len(label), len(context)))
    with open('ut_tls_hkdf_lbl_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(label+context)
    with open('ut_tls_hkdf_lbl_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (hkdf_lbl.hex()))
    return hkdf_lbl
'''


def tls_derive_key_iv(csuite, secret):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    # DOUBLE CHECKED - APPEARS CORRECT
    key_length = tls_constants.KEY_LEN[csuite]
    iv_length = tls_constants.IV_LEN[csuite]
    key_hkdf = HKDF(csuite)
    iv_hkdf = HKDF(csuite)
    key_label = tls_hkdf_label("key".encode(), "".encode(), key_length)
    iv_label = tls_hkdf_label("iv".encode(), "".encode(), iv_length)
    key = key_hkdf.tls_hkdf_expand(secret, key_label, key_length)
    iv = iv_hkdf.tls_hkdf_expand(secret, iv_label, iv_length)
    return key, iv


'''
def tls_test_derive_key_iv(csuite, secret):
    ##########################
    # THIS IS TO BE ASSESSED
    ##########################
    key_length = tls_constants.KEY_LEN[csuite]
    iv_length = tls_constants.IV_LEN[csuite]
    key_hkdf = HKDF(csuite)
    iv_hkdf = HKDF(csuite)
    key_label = tls_hkdf_label("key".encode(), "".encode(), key_length)
    iv_label = tls_hkdf_label("iv".encode(), "".encode(), iv_length)
    key = key_hkdf.tls_hkdf_expand(secret, key_label, key_length)
    iv = iv_hkdf.tls_hkdf_expand(secret, iv_label, iv_length)
    with open('ut_tls_derive_key_iv_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d\n' % (csuite, len(secret)))
    with open('ut_tls_derive_key_iv_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(secret)
    with open('ut_tls_derive_key_iv_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s %s\n' % (key.hex(), iv.hex()))
    return key, iv
'''


def tls_extract_secret(csuite, keying_material, salt):
    ##########################
    # THIS IS TO BE ASSESSED
    ##########################
    # DOUBLE CHECKED - APPEARS CORRECT
    hkdf = HKDF(csuite)
    secret = hkdf.tls_hkdf_extract(keying_material, salt)
    return secret


'''
def tls_test_extract_secret(csuite, keying_material, salt):
    ##########################
    # THIS IS TO BE ASSESSED
    ##########################
    ## DOUBLE CHECKED - APPEARS CORRECT
    hkdf = HKDF(csuite)
    secret = hkdf.tls_hkdf_extract(keying_material, salt)
    if (keying_material == None):
        len_key_mat = 0
        keying_material = "".encode()
    else:
        len_key_mat = len(keying_material)
    if (salt == None):
        len_salt = 0
        salt = "".encode()
    else:
        len_salt = len(salt)
    with open('ut_tls_extract_secret_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %d\n' % (csuite, len_key_mat, len_salt))
    with open('ut_tls_extract_secret_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(keying_material+salt)
    with open('ut_tls_extract_secret_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (secret.hex()))
    return secret
'''


def tls_derive_secret(csuite, secret, label, messages):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    # DOUBLE CHECKED - APPEARS CORRECT
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash = SHA256.new()
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash = SHA384.new()
    hash_length = hash.digest_size
    hkdf = HKDF(csuite)
    transcript_hash = tls_transcript_hash(csuite, messages)
    secret_label = tls_hkdf_label(label, transcript_hash, hash_length)
    secret = hkdf.tls_hkdf_expand(secret, secret_label, hash_length)
    return secret


'''
def tls_test_derive_secret(csuite, in_secret, label, messages):
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash=SHA256.new()
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash=SHA384.new()
    hash_length = hash.digest_size
    hkdf = HKDF(csuite)
    transcript_hash = tls_transcript_hash(csuite, messages)
    secret_label = tls_hkdf_label(label, transcript_hash, hash_length)
    out_secret = hkdf.tls_hkdf_expand(in_secret, secret_label, hash_length)
    with open('ut_tls_derive_secret_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %d %d\n' % (csuite, len(in_secret), len(label), len(messages)))
    with open('ut_tls_derive_secret_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(in_secret+label+messages)
    with open('ut_tls_derive_secret_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (out_secret.hex()))
    return out_secret
'''


def tls_finished_key_derive(csuite, secret):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    # DOUBLE CHECKED - APPEARS CORRECT
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash = SHA256.new()
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash = SHA384.new()
    hash_length = hash.digest_size
    hkdf = HKDF(csuite)
    finished_label = tls_hkdf_label(
        "finished".encode(), "".encode(), hash_length)
    finished_key = hkdf.tls_hkdf_expand(secret, finished_label, hash_length)
    return finished_key


'''
def tls_test_finished_key_derive(csuite, secret):
    ##########################
    # THIS IS TO BE ASSESSED
    ##########################
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash=SHA256.new()
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash=SHA384.new()
    hash_length = hash.digest_size
    hkdf = HKDF(csuite)
    finished_label = tls_hkdf_label("finished".encode(), "".encode(), hash_length)
    finished_key = hkdf.tls_hkdf_expand(secret, finished_label, hash_length)
    with open('ut_tls_finished_key_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d\n' % (csuite, len(secret)))
    with open('ut_tls_finished_key_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(secret)
    with open('ut_tls_finished_key_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (finished_key.hex()))
    return finished_key
'''


def tls_finished_mac(csuite, key, context):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    # DOUBLE CHECKED - APPEARS CORRECT
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash = SHA256.new()
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash = SHA384.new()
    hmac = HMAC.new(key, context, hash)
    tag = hmac.digest()
    return tag


'''
def tls_test_finished_mac(csuite, key, context):
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash=SHA256.new()
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash=SHA384.new()
    hmac = HMAC.new(key, context, hash)
    tag = hmac.digest()
    with open('ut_tls_finished_mac_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %d\n' % (csuite, len(key), len(context)))
    with open('ut_tls_finished_mac_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(key+context)
    with open('ut_tls_finished_mac_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (tag.hex()))
    return tag
'''


def tls_finished_mac_verify(csuite, key, context, tag):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    # DOUBLE CHECKED - APPEARS CORRECT
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash = SHA256.new()
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash = SHA384.new()
    hmac = HMAC.new(key, context, hash)
    hmac.verify(tag)


'''
def tls_test_finished_mac_verify(csuite, key, context, tag):
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
        hash=SHA256.new()
    if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        hash=SHA384.new()
    hmac = HMAC.new(key, context, hash)
    hmac.verify(tag)
    with open('ut_tls_finished_mac_vfy_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %d %d\n' % (csuite, len(key), len(context), len(tag)))
    with open('ut_tls_finished_mac_vfy_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(key+context+tag)
'''


def tls_aead_encrypt(csuite, key, nonce, plaintext):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        cipher = AES.new(key, AES.MODE_GCM, nonce)
    else:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    legacy_type_bytes = tls_constants.APPLICATION_TYPE.to_bytes(1, 'big')
    legacy_vers_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
    len_ctxt = len(plaintext) + tls_constants.MAC_LEN[csuite]
    len_bytes = len_ctxt.to_bytes(2, 'big')
    add_data = legacy_type_bytes + legacy_vers_bytes + len_bytes
    cipher.update(add_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    ctxt = ciphertext + tag
    return ctxt


'''
def tls_test_aead_encrypt(csuite, key, nonce, plaintext):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        cipher = AES.new(key, AES.MODE_GCM, nonce)
    else:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    legacy_type_bytes = tls_constants.APPLICATION_TYPE.to_bytes(1,'big')
    legacy_vers_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
    len_ctxt = len(plaintext) + tls_constants.MAC_LEN[csuite]
    len_bytes = len_ctxt.to_bytes(2, 'big')
    add_data = legacy_type_bytes + legacy_vers_bytes + len_bytes
    cipher.update(add_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    ctxt = ciphertext + tag
    with open('ut_tls_aead_encrypt_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %d %d\n' % (csuite, len(key), len(nonce), len(plaintext)))
    with open('ut_tls_aead_encrypt_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(key+nonce+plaintext)
    with open('ut_tls_aead_encrypt_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (ctxt.hex()))
    return ctxt
'''


def tls_aead_decrypt(csuite, key, nonce, ciphertext):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        cipher = AES.new(key, AES.MODE_GCM, nonce)
    else:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    aead_ctxt_len = len(ciphertext)
    mac_len = tls_constants.MAC_LEN[csuite]
    ctxt_len = aead_ctxt_len - mac_len
    ctxt = ciphertext[:ctxt_len]
    tag = ciphertext[ctxt_len:]
    legacy_type_bytes = tls_constants.APPLICATION_TYPE.to_bytes(1, 'big')
    legacy_vers_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
    len_bytes = aead_ctxt_len.to_bytes(2, 'big')
    add_data = legacy_type_bytes + legacy_vers_bytes + len_bytes
    cipher.update(add_data)
    plaintext = cipher.decrypt_and_verify(ctxt, tag)
    return plaintext


'''
def tls_test_aead_decrypt(csuite, key, nonce, ciphertext):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
        cipher = AES.new(key, AES.MODE_GCM, nonce)
    else:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    aead_ctxt_len = len(ciphertext)
    mac_len = tls_constants.MAC_LEN[csuite]
    ctxt_len = aead_ctxt_len - mac_len
    ctxt = ciphertext[:ctxt_len]
    tag = ciphertext[ctxt_len:]
    legacy_type_bytes = tls_constants.APPLICATION_TYPE.to_bytes(1,'big')
    legacy_vers_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
    len_bytes = aead_ctxt_len.to_bytes(2, 'big')
    add_data = legacy_type_bytes + legacy_vers_bytes + len_bytes
    cipher.update(add_data)
    plaintext = cipher.decrypt_and_verify(ctxt, tag)
    with open('ut_tls_aead_decrypt_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %d %d\n' % (csuite, len(key), len(nonce), len(ciphertext)))
    with open('ut_tls_aead_decrypt_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(key+nonce+ciphertext)
    with open('ut_tls_aead_decrypt_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (plaintext.hex()))
    return plaintext
'''


def tls_nonce(csuite, sqn_no, iv):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    iv_length = tls_constants.IV_LEN[csuite]
    sqn_no_bytes = sqn_no.to_bytes(8, 'big')
    pad_len = iv_length - len(sqn_no_bytes)
    pad = b'\0'*pad_len
    sqn_no_bytes = pad + sqn_no_bytes
    nonce = xor_bytes(sqn_no_bytes, iv)
    return nonce


'''
def tls_test_nonce(csuite, sqn_no, iv):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    iv_length = tls_constants.IV_LEN[csuite]
    sqn_no_bytes = sqn_no.to_bytes(8, 'big')
    pad_len = iv_length - len(sqn_no_bytes)
    pad = b'\0'*pad_len
    sqn_no_bytes = pad + sqn_no_bytes 
    nonce = xor_bytes(sqn_no_bytes, iv)
    with open('ut_tls_nonce_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %d\n' % (csuite, sqn_no, len(iv)))
    with open('ut_tls_nonce_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(iv)
    with open('ut_tls_nonce_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (nonce.hex()))
    return nonce
'''


def tls_signature_context(context_flag, content):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    if (context_flag == tls_constants.SERVER_FLAG):
        context = "TLS 1.3, server CertificateVerify"
    if (context_flag == tls_constants.CLIENT_FLAG):
        context = "TLS 1.3, client CertificateVerify"
    prefix_byte = 0x20.to_bytes(1, 'big')
    prefix_bytes = "".encode()
    for i in range(64):
        prefix_bytes = prefix_bytes + prefix_byte
    seperator_byte = 0x00.to_bytes(1, 'big')
    message = prefix_bytes + context.encode() + seperator_byte + content
    return message


'''
def tls_test_signature_context(context_flag, content):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    if (context_flag == tls_constants.SERVER_FLAG):
        context = "TLS 1.3, server CertificateVerify"
    if (context_flag == tls_constants.CLIENT_FLAG):
        context = "TLS 1.3, client CertificateVerify"
    prefix_byte = 0x20.to_bytes(1, 'big')
    prefix_bytes = "".encode()
    for i in range(64):
        prefix_bytes = prefix_bytes + prefix_byte
    seperator_byte = 0x00.to_bytes(1, 'big')
    message = prefix_bytes + context.encode() + seperator_byte + content
    with open('ut_tls_sig_context_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%s %d\n' % (context_flag, len(content)))
    with open('ut_tls_sig_context_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(content)
    with open('ut_tls_sig_context_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (message.hex()))
    return message
'''


def tls_signature(signature_algorithm, msg, context_flag):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    message = tls_signature_context(context_flag, msg)
    if (signature_algorithm == tls_constants.RSA_PKCS1_SHA256):
        secret_key = tls_constants.RSA2048_KEY
        signer = pkcs1_15.new(secret_key)
        hash = SHA256.new()
        hash.update(message)
        signature = signer.sign(hash)
    if (signature_algorithm == tls_constants.RSA_PKCS1_SHA384):
        secret_key = tls_constants.RSA2048_KEY
        signer = pkcs1_15.new(secret_key)
        hash = SHA384.new()
        hash.update(message)
        signature = signer.sign(hash)
    if (signature_algorithm == tls_constants.ECDSA_SECP384R1_SHA384):
        secret_key = tls_constants.SECP384R1_KEY
        signer = DSS.new(secret_key, 'fips-186-3')
        hash = SHA384.new()
        hash.update(message)
        signature = signer.sign(hash)
    if (signature_algorithm == tls_constants.RING_SECP256K1_SHA256):
        secret_key = tls_constants.SECP256K1_KEY
        pkeys, mypair = aosring.aosring_prepkeys(secret_key)
        # print("Public keys: ", pkeys)
        # print("My pair: ", mypair)
        # print("Message: ", message)
        signature = aosring.aosring_sign(
            pkeys, mypair, message=bytes_to_int(message))
        # print("Signature: ", signature)
        # return byte string of sig
    return signature


'''
def tls_test_signature(signature_algorithm, msg, context_flag):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    message = tls_signature_context(context_flag, msg)
    if (signature_algorithm == tls_constants.RSA_PKCS1_SHA256):
        secret_key = tls_constants.RSA2048_KEY
        signer = pkcs1_15.new(secret_key)
        hash = SHA256.new()
        hash.update(message)
        signature = signer.sign(hash)
    if (signature_algorithm == tls_constants.RSA_PKCS1_SHA384):
        secret_key = tls_constants.RSA2048_KEY
        signer = pkcs1_15.new(secret_key)
        hash = SHA384.new()
        hash.update(message)
        signature = signer.sign(hash)
    if (signature_algorithm == tls_constants.ECDSA_SECP384R1_SHA384):
        secret_key = tls_constants.SECP384R1_KEY
        signer = DSS.new(secret_key, 'fips-186-3')
        hash = SHA384.new()
        hash.update(message)
        signature = signer.sign(hash)
    with open('ut_tls_signature_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %s\n' % (signature_algorithm, len(msg), context_flag))
    with open('ut_tls_signature_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(msg)
    with open('ut_tls_signature_outputs.txt', 'a') as filehandle:
        filehandle.write('\n%s\n' % (signature.hex()))
    return signature
'''


def tls_verify_signature(signature_algorithm, message, context_flag, signature, public_key):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    ctx_message = tls_signature_context(context_flag, message)
    if (signature_algorithm == tls_constants.RSA_PKCS1_SHA256):
        verifier = pkcs1_15.new(public_key)
        hash = SHA256.new()
        hash.update(ctx_message)
        verifier.verify(hash, signature)
    if (signature_algorithm == tls_constants.RSA_PKCS1_SHA384):
        verifier = pkcs1_15.new(public_key)
        hash = SHA384.new()
        hash.update(ctx_message)
        verifier.verify(hash, signature)
    if (signature_algorithm == tls_constants.ECDSA_SECP384R1_SHA384):
        verifier = DSS.new(public_key, 'fips-186-3')
        hash = SHA384.new()
        hash.update(ctx_message)
        verifier.verify(hash, signature)
    if (signature_algorithm == tls_constants.RING_SECP256K1_SHA256):
        aosring.aosring_check(signature, bytes_to_int(ctx_message))


'''
def tls_test_verify_signature(signature_algorithm, message, context_flag, signature, public_key):
    #########################
    # THIS IS TO BE ASSESSED
    #########################
    ctx_message = tls_signature_context(context_flag, message)
    if (signature_algorithm == tls_constants.RSA_PKCS1_SHA256):
        verifier = pkcs1_15.new(public_key)
        hash = SHA256.new()
        hash.update(ctx_message)
        result = verifier.verify(hash, signature)
    if (signature_algorithm == tls_constants.RSA_PKCS1_SHA384):
        verifier = pkcs1_15.new(public_key)
        hash = SHA384.new()
        hash.update(ctx_message)
        result = verifier.verify(hash, signature)
    if (signature_algorithm == tls_constants.ECDSA_SECP384R1_SHA384):
        verifier = DSS.new(public_key, 'fips-186-3')
        hash = SHA384.new()
        hash.update(ctx_message)
        result = verifier.verify(hash, signature)
    with open('ut_tls_signature_vfy_int_inputs.txt', 'a') as filehandle:
        filehandle.write('\n%d %d %s %d\n' % (signature_algorithm, len(message), context_flag, len(signature)))
    with open('ut_tls_signature_vfy_byte_inputs.txt', 'ab') as filehandle:
        filehandle.write(message+signature)
'''
