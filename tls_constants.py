#!/usr/bin/env python

'''
tls_constants.py:
Contains the flags needed throughout the handshake, alert and record protocols
'''

from Cryptodome.PublicKey import RSA, ECC

INVALID_TYPE = 0
CHANGE_TYPE = 20
ALERT_TYPE = 21
HANDSHAKE_TYPE = 22
APPLICATION_TYPE = 23
LEGACY_VERSION = 0x0303
TLS_13_PROTOCOL_VERSION = 0x0303
AES_BLOCK_LEN = 16
SHA_256_LEN = 32
SHA_384_LEN = 48
POLY_1305_LEN = 16
RECORD_READ = "r"
RECORD_WRITE = "w"
CCHELO_STATE = "CHELO"
SHELO_STATE = "SHELO"
INIT_STATE = "INIT"
CLIENT_FLAG = "CLIENT"
SERVER_FLAG = "SERVER"
EARLY_FLAG = "EARLY"
HSHAKE_FLAG = "HSHAKE"
MASTER_FLAG = "MASTER"
RECORD_PREFIX_LEN = 5
MAX_RECORD_LEN = 2**14 + 256 + 5

# RECORD FIELD LENGTHS
CONTENT_TYPE_LEN = 1
RECORD_LENGTH_LEN = 2
PROTOCOL_VERSION_LEN = 2

### HANDSHAKE MESSAGE TYPES
CHELO_TYPE = 1
SHELO_TYPE = 2
NEWST_TYPE = 4
EOED_TYPE  = 5
ENEXT_TYPE = 8
CERT_TYPE = 11
CREQ_TYPE = 13
CVFY_TYPE = 15
FINI_TYPE = 20
KEYU_TYPE = 24
MSGH_TYPE = 254

# FIELD LENGTHs
MSG_TYPE_LEN = 1
MSG_LEN_LEN = 3
MSG_VERS_LEN = 2
HEAD_LEN_LEN = 2
RANDOM_LEN = 32
SID_LEN_LEN = 1
CSUITE_LEN_LEN = 2
COMP_LEN_LEN = 1
CSUITE_LEN = 2
EXT_LEN_LEN = 2
SEL_ID_LEN = 2

### CIPHERSUITE FLAGS
TLS_13_NEG_VERSION = 0x0304
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303
KEY_LEN = {
    TLS_AES_128_GCM_SHA256: 16,
    TLS_AES_256_GCM_SHA384: 32,
    TLS_CHACHA20_POLY1305_SHA256: 32
}
MAC_LEN = {
    TLS_AES_128_GCM_SHA256: 16,
    TLS_AES_256_GCM_SHA384: 16,
    TLS_CHACHA20_POLY1305_SHA256: 16
}
IV_LEN = {
    TLS_AES_128_GCM_SHA256: 12,
    TLS_AES_256_GCM_SHA384: 12,
    TLS_CHACHA20_POLY1305_SHA256: 12
}
CLIENT_SUPPORTED_CIPHERSUITES = [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]
#CLIENT_SUPPORTED_CIPHERSUITES = [TLS_AES_128_GCM_SHA256]
#CLIENT_SUPPORTED_CIPHERSUITES = [TLS_AES_256_GCM_SHA384]
#CLIENT_SUPPORTED_CIPHERSUITES = [TLS_CHACHA20_POLY1305_SHA256]
SERVER_SUPPORTED_CIPHERSUITES = [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]
#SERVER_SUPPORTED_CIPHERSUITES = [TLS_AES_128_GCM_SHA256]
#SERVER_SUPPORTED_CIPHERSUITES = [TLS_AES_256_GCM_SHA384]
#SERVER_SUPPORTED_CIPHERSUITES = [TLS_CHACHA20_POLY1305_SHA256]

#VARIOUS EXTENSIONS
SERVER_NAME_EXT_TYPE = 0
MAX_FRAG_LEN_TYPE = 1
STATUS_REQ_TYPE = 5
USE_SRTP_TYPE = 14
HEARTBEAT_TYPE = 15
APP_PROT_NEG_TYPE = 16
SIGN_CERT_TS_TYPE = 18
PADDING_TYPE = 21
PSK_TYPE = 41
EARLY_DATA_TYPE = 42
COOKIE_TYPE = 44
PSK_KEX_MODE_TYPE = 45
CERT_AUTH_TYPE = 47
OID_FILTER_TYPE = 48
POST_HS_AUTH_TYPE = 49
SIG_ALGS_CERT_TYPE = 50
PSK_KE_MODE = 0
PSK_DHE_KE_MODE = 1

### SUPPORTED DIFFIE_HELLMAN GROUPS
### AND TINYEC FLAGS FOR EACH
SUPPORT_GROUPS_TYPE = 10
SECP256R1_VALUE = 0x0017
SECP256R1_FLAG = "secp256r1"
SECP384R1_VALUE = 0x0018
SECP384R1_FLAG = "secp384r1"
SECP521R1_VALUE = 0x0019
SECP521R1_FLAG = "secp521r1"
CLIENT_SUPPORTED_GROUPS = [SECP256R1_VALUE, SECP384R1_VALUE, SECP521R1_VALUE]
#CLIENT_SUPPORTED_GROUPS = [SECP256R1_VALUE]
#CLIENT_SUPPORTED_GROUPS = [SECP384R1_VALUE]
#CLIENT_SUPPORTED_GROUPS = [SECP521R1_VALUE]
SERVER_SUPPORTED_GROUPS = [SECP256R1_VALUE, SECP384R1_VALUE, SECP521R1_VALUE]
#SERVER_SUPPORTED_GROUPS = [SECP256R1_VALUE]
#SERVER_SUPPORTED_GROUPS = [SECP384R1_VALUE]
#SERVER_SUPPORTED_GROUPS = [SECP521R1_VALUE]

GROUP_FLAGS = {
    SECP256R1_VALUE: SECP256R1_FLAG,
    SECP384R1_VALUE: SECP384R1_FLAG,
    SECP521R1_VALUE: SECP521R1_FLAG
}
COORD_LEN = {
    SECP256R1_VALUE: 32,
    SECP384R1_VALUE: 48,
    SECP521R1_VALUE: 66
}

### SUPPORTED SIGNATURE SCHEMES
SIG_ALGS_TYPE = 13
RSA_PKCS1_SHA256 = 0x0401
RSA_PKCS1_SHA384 = 0x0501
RSA_PKCS1_SHA512 = 0x0601
ECDSA_SECP256R1_SHA256 = 0x0403
ECDSA_SECP384R1_SHA384 = 0x0503
ECDSA_SECP521R1_SHA512 = 0x0603
CLIENT_SUPPORTED_SIGS = [RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, ECDSA_SECP384R1_SHA384]
#CLIENT_SUPPORTED_SIGS = [RSA_PKCS1_SHA256]
#CLIENT_SUPPORTED_SIGS = [RSA_PKCS1_SHA384]
#CLIENT_SUPPORTED_SIGS = [ECDSA_SECP384R1_SHA384]
SERVER_SUPPORTED_SIGS = [RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, ECDSA_SECP384R1_SHA384]
#SERVER_SUPPORTED_SIGS = [RSA_PKCS1_SHA256]
#SERVER_SUPPORTED_SIGS = [RSA_PKCS1_SHA384]
#SERVER_SUPPORTED_SIGS = [ECDSA_SECP384R1_SHA384]

### SUPPORTED CERTIFICATES
CLIENT_CERT_TYPE = 19
SERVER_CERT_TYPE = 20

### SUPPORTED VERSION NEGOTIATION
SUPPORT_VERS_TYPE = 43
SUPPORTED_VERSIONS = [TLS_13_NEG_VERSION]

### DIFFIE-HELLMAN KEYSHARE EXTENSION
KEY_SHARE_TYPE = 51

### EXTENSIONS SUPPORTED BY THIS IMPLEMENTATION
SERVER_SUPPORTED_EXTENSIONS = {
    SUPPORT_VERS_TYPE: SUPPORTED_VERSIONS,
    SUPPORT_GROUPS_TYPE: SERVER_SUPPORTED_GROUPS,
    SIG_ALGS_TYPE: SERVER_SUPPORTED_SIGS
}

CLIENT_SUPPORTED_EXTENSIONS = {
    SUPPORT_VERS_TYPE: SUPPORTED_VERSIONS,
    SUPPORT_GROUPS_TYPE: CLIENT_SUPPORTED_GROUPS,
    SIG_ALGS_TYPE: CLIENT_SUPPORTED_SIGS
}

RSA2048_SHA256_CERT_FILE = "./rsa_2048_sha_256_certificate.pem"
RSA2048_SHA384_CERT_FILE = "./rsa_2048_sha_384_certificate.pem"
RSA2048_KEY_FILE = "./rsa_2048_privkey.pem"
SECP384R1_SHA384_CERT_FILE = "./secp384r1_sha_384_certificate.pem"
SECP384R1_KEY_FILE = "secp384r1_privkey.pem"
RSA2048_KEY = RSA.import_key(open(RSA2048_KEY_FILE).read())
RSA2048_SHA256_CERT = open(RSA2048_SHA256_CERT_FILE).read()
RSA2048_SHA384_CERT = open(RSA2048_SHA384_CERT_FILE).read()
SECP384R1_SHA384_CERT = open(SECP384R1_SHA384_CERT_FILE).read()
SECP384R1_KEY = ECC.import_key(open(SECP384R1_KEY_FILE).read())

SERVER_SUPPORTED_CERTIFICATES = {
    RSA_PKCS1_SHA256: RSA2048_SHA256_CERT,
    RSA_PKCS1_SHA384: RSA2048_SHA384_CERT,
    ECDSA_SECP384R1_SHA384: SECP384R1_SHA384_CERT
}

## TLS ALERT VALUES
## LEVEL-OF-ERROR FLAGS
TLS_ERROR_WARN_LVL = 1
TLS_ERROR_FATAL_LVL = 2

## TYPE-OF-ERROR FLAGS
TLS_CLOSE_NOTIFY = 0
TLS_UNEXP_MSG = 10
TLS_BAD_REC_MAC = 20
TLS_REC_OVERFLOW = 22
TLS_HS_FAIL = 40
TLS_BAD_CERT = 42
TLS_UNSUPPORT_CERT = 43
TLS_REVOKE_CERT = 44
TLS_EXPIRE_CERT = 45
TLS_UNKNOWN_CERT = 46
TLS_ILLEGAL_PARA = 47
TLS_UNKNOWN_CA = 48
TLS_ACCESS_DENIED = 49
TLS_DECODE_ERROR = 50
TLS_DECRYPT_ERROR = 51
TLS_PROT_VERSION = 70
TLS_LOW_SECURITY = 71
TLS_INTERNAL_ERROR = 80
TLS_BAD_FALLBACK = 86
TLS_USER_CANCEL = 90
TLS_MISSING_EXTEN = 109
TLS_UNSUPPORT_EXTEN = 110
TLS_UNRECOGNISED_NAME = 112
TLS_BAD_CERT_STATUS = 113
TLS_UNKNOWN_PSK = 115
TLS_REQUIRE_CERT = 116
TLS_NO_APP_PROT = 120
