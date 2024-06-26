#!/usr/bin/env python

'''
tls_handshake.py:
Implementation of the TLS 1.3 Handshake Protocol
'''

from typing import Dict, List, Tuple
from Cryptodome.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import (StateConfusionError, InvalidMessageStructureError,
                       WrongRoleError)
import tls_extensions


class Handshake:
    "This is the class for the handshake protocol"

    def __init__(self, csuites: List[int], extensions: Dict[int, List[int]], role: int):
        self.csuites = csuites
        self.extensions = extensions
        self.state = tls_constants.INIT_STATE
        self.role = role
        self.csuite = None

        self.master_secret = None
        self.client_hs_traffic_secret = None
        self.server_hs_traffic_secret = None
        self.client_ap_traffic_secret = None
        self.server_ap_traffic_secret = None

        self.ec_sec_keys = {}
        self.ec_sec_key = None
        self.ec_pub_key = None
        self.pub_key = None

        self.server_cert = None
        self.server_cert_string = None

        self.neg_group = None
        self.neg_version = None
        self.signature = None
        self.sid = None
        self.chelo = None
        self.remote_csuites = None
        self.num_remote_csuites = None
        self.remote_extensions = None

        self.transcript = "".encode()
        self.get_random_bytes = get_random_bytes

    def tls_13_compute_server_hs_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.server_hs_traffic_secret == None:
            raise StateConfusionError()
        handshake_key, handshake_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.server_hs_traffic_secret)
        return handshake_key, handshake_iv, self.csuite

    def tls_13_compute_client_hs_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.client_hs_traffic_secret == None:
            raise StateConfusionError()
        handshake_key, handshake_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_hs_traffic_secret)
        return handshake_key, handshake_iv, self.csuite

    def tls_13_compute_server_ap_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE An APPLICATION KEY
        if self.server_ap_traffic_secret == None:
            raise StateConfusionError()
        application_key, application_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.server_ap_traffic_secret)
        return application_key, application_iv, self.csuite

    def tls_13_compute_client_ap_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE AN APPLICATION KEY
        if self.client_ap_traffic_secret == None:
            raise StateConfusionError()
        application_key, application_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_ap_traffic_secret)
        return application_key, application_iv, self.csuite

    def attach_handshake_header(self, msg_type: int, msg: bytes) -> bytes:
        len_msg = len(msg).to_bytes(3, 'big')
        hs_msg_type = msg_type.to_bytes(1, 'big')
        return hs_msg_type + len_msg + msg

    def process_handshake_header(self, msg_type: int, msg: bytes) -> bytes:
        curr_pos = 0
        curr_msg_type = msg[curr_pos]
        if curr_msg_type != msg_type:
            raise InvalidMessageStructureError()
        curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
        msg_len = int.from_bytes(
            msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
        ptxt_msg = msg[curr_pos:]
        if msg_len != len(ptxt_msg):
            raise InvalidMessageStructureError()
        return ptxt_msg

    def tls_13_client_hello(self) -> bytes:
        #########################
        # THIS IS TO BE ASSESSED
        #########################
        if self.state != tls_constants.INIT_STATE:
            raise StateConfusionError()
        if self.role != tls_constants.CLIENT_FLAG:
            raise WrongRoleError()
        # ALL OF THE LEGACY TLS CLIENTHELLO INFORMATION
        # Must be set like this for compatability reasons
        legacy_vers = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
        # Must be set like this for compatability reasons
        random = get_random_bytes(32)
        # Must be set like this for compatability reasons
        legacy_sess_id = get_random_bytes(32)
        # NEED TO SAVE THE SESSION ID TO VERIFY THE SERVER SESSION ID LATER
        self.sid = legacy_sess_id
        legacy_sess_id_len = len(legacy_sess_id).to_bytes(1, 'big')
        # AT THIS POINT WE ATTACH OUR LIST OF CLIENT SUPPORTED CIPHERSUITES
        csuites_bytes = "".encode()
        for i in range(len(self.csuites)):
            csuite_bytes = self.csuites[i].to_bytes(2, 'big')
            csuites_bytes = csuites_bytes + csuite_bytes
        csuites_len = len(csuites_bytes).to_bytes(2, 'big')
        # LEGACY COMPRESSION FIELDS
        # Must be set like this for compatability reasons
        legacy_compression = 0x00.to_bytes(1, 'big')
        # Must be set like this for compatability reasons
        comp_len = len(legacy_compression).to_bytes(
            tls_constants.COMP_LEN_LEN, 'big')

        # WE BEGIN WITH VERSION NEGOTIATION
        supported_vers_ext = tls_extensions.prep_support_vers_ext(
            self.extensions)
        # WE CONTINUE WITH GROUP NEGOTIATION
        supported_group_ext = tls_extensions.prep_support_groups_ext(
            self.extensions)
        # WE ARE NOW DOING SOME KEYSHARE EXTENSIONS
        # REMEMBER THAT WE NEED TO SAVE THE EC_SEC_KEYS TO STATE
        # FOR WHEN WE RECEIVE THE SERVERHELLO TO DERIVE THE
        # VARIOUS SECRET VALUES, DEPENDING ON WHAT GROUP THE SERVER CHOOSES
        keyshare_ext, self.ec_sec_keys = tls_extensions.prep_keyshare_ext(
            self.extensions)
        # AND SIGNATURE EXTENSIONS
        signature_ext = tls_extensions.prep_signature_ext(self.extensions)

        # HERE WE ATTACH ALL OF OUR EXTENSIONS
        extensions = supported_vers_ext + supported_group_ext + keyshare_ext + signature_ext
        exten_len = len(extensions).to_bytes(2, 'big')
        # WE CAN NOW CONSTRUCT OUR CLIENTHELLO MESSAGE
        chelo_msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + \
            csuites_len + csuites_bytes + comp_len + \
            legacy_compression + exten_len + extensions
        # AND CREATE OUR TLS CLIENTHELLO HANDSHAKE HEADER
        client_hello_msg = self.attach_handshake_header(
            tls_constants.CHELO_TYPE, chelo_msg)
        # UPDATE STATE SO OUR IMPLEMENTATION DOESN'T LOSE
        # WHERE IT CURRENTLY IS IN STATE
        self.state = tls_constants.CCHELO_STATE
        self.chelo = client_hello_msg
        self.transcript = self.transcript + client_hello_msg
        return client_hello_msg

    def tls_13_process_client_hello(self, chelo_msg: bytes):
        # DECONSTRUCT OUR CLIENTHELLO MESSAGE
        chelo = self.process_handshake_header(
            tls_constants.CHELO_TYPE, chelo_msg)
        curr_pos = 0
        chelo_vers = chelo[curr_pos:curr_pos + tls_constants.MSG_VERS_LEN]
        curr_pos = curr_pos + tls_constants.MSG_VERS_LEN
        chelo_rand = chelo[curr_pos:curr_pos + tls_constants.RANDOM_LEN]
        curr_pos = curr_pos + tls_constants.RANDOM_LEN
        chelo_sess_id_len = chelo[curr_pos]
        curr_pos = curr_pos + tls_constants.SID_LEN_LEN
        self.sid = chelo[curr_pos:curr_pos+chelo_sess_id_len]
        curr_pos = curr_pos+chelo_sess_id_len
        csuites_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.CSUITE_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.CSUITE_LEN_LEN
        self.remote_csuites = chelo[curr_pos:curr_pos+csuites_len]
        curr_pos = curr_pos + csuites_len
        self.num_remote_csuites = csuites_len//tls_constants.CSUITE_LEN
        comp_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.COMP_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.COMP_LEN_LEN
        legacy_comp = chelo[curr_pos]
        if legacy_comp != 0x00:
            raise InvalidMessageStructureError()
        curr_pos = curr_pos + comp_len
        exts_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.EXT_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.EXT_LEN_LEN
        self.remote_extensions = chelo[curr_pos:curr_pos+exts_len]
        self.transcript = self.transcript + chelo_msg

    def tls_13_server_get_remote_extensions(self) -> Dict[str, bytes]:
        curr_ext_pos = 0
        remote_extensions = {}
        while curr_ext_pos < len(self.remote_extensions):
            ext_type = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_len = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_bytes = self.remote_extensions[curr_ext_pos:curr_ext_pos+ext_len]
            if ext_type == tls_constants.SUPPORT_VERS_TYPE:
                remote_extensions['supported versions'] = ext_bytes
            if ext_type == tls_constants.SUPPORT_GROUPS_TYPE:
                remote_extensions['supported groups'] = ext_bytes
            if ext_type == tls_constants.KEY_SHARE_TYPE:
                remote_extensions['key share'] = ext_bytes
            if ext_type == tls_constants.SIG_ALGS_TYPE:
                remote_extensions['sig algs'] = ext_bytes
            curr_ext_pos = curr_ext_pos + ext_len
        return remote_extensions

    def tls_13_server_select_parameters(self, remote_extensions: Dict[str, bytes]):
        self.neg_version = tls_extensions.negotiate_support_vers_ext(
            self.extensions, remote_extensions['supported versions'])
        self.neg_group = tls_extensions.negotiate_support_group_ext(
            self.extensions, remote_extensions['supported groups'])

        (self.pub_key, self.neg_group, self.ec_pub_key,
         self.ec_sec_key) = tls_extensions.negotiate_keyshare(
            self.extensions, self.neg_group, remote_extensions['key share'])

        self.signature = tls_extensions.negotiate_signature_ext(
            self.extensions, remote_extensions['sig algs'])
        self.csuite = tls_extensions.negotiate_support_csuite(
            self.csuites, self.num_remote_csuites, self.remote_csuites)

    def tls_13_prep_server_hello(self) -> bytes:
        # ALL OF THE LEGACY TLS SERVERHELLO INFORMATION
        # Must be set like this for compatability reasons
        legacy_vers = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
        # Must be set like this for compatability reasons
        random = get_random_bytes(32)
        legacy_sess_id = self.sid  # Must be set like this for compatability reasons
        legacy_sess_id_len = len(self.sid).to_bytes(1, 'big')
        legacy_compression = (0x00).to_bytes(1, 'big')
        csuite_bytes = self.csuite.to_bytes(2, 'big')
        # WE ATTACH ALL OUR EXTENSIONS
        neg_vers_ext = tls_extensions.finish_support_vers_ext(self.neg_version)
        neg_group_ext = tls_extensions.finish_support_group_ext(self.neg_group)
        supported_keyshare = tls_extensions.finish_keyshare_ext(
            self.pub_key, self.neg_group)
        extensions = neg_vers_ext + neg_group_ext + supported_keyshare
        exten_len = len(extensions).to_bytes(2, 'big')
        msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + \
            csuite_bytes + legacy_compression + exten_len + extensions
        shelo_msg = self.attach_handshake_header(tls_constants.SHELO_TYPE, msg)
        self.transcript += shelo_msg
        early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())
        ecdh_secret_point = tls_crypto.ec_dh(self.ec_sec_key, self.ec_pub_key)
        ecdh_secret = tls_crypto.point_to_secret(
            ecdh_secret_point, self.neg_group)
        handshake_secret = tls_crypto.tls_extract_secret(
            self.csuite, ecdh_secret, derived_early_secret)
        self.server_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "s hs traffic".encode(), self.transcript)
        self.client_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "c hs traffic".encode(), self.transcript)
        derived_hs_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "derived".encode(), "".encode())
        self.master_secret = tls_crypto.tls_extract_secret(
            self.csuite, None, derived_hs_secret)
        return shelo_msg

    def tls_13_process_server_hello(self, shelo_msg: bytes):
        #########################
        # THIS IS TO BE ASSESSED
        #########################
        # first_transcript = self.transcript
        shelo = self.process_handshake_header(
            tls_constants.SHELO_TYPE, shelo_msg)
        msg_len = len(shelo)
        curr_pos = 0
        legacy_vers = int.from_bytes(shelo[curr_pos:curr_pos + 2], 'big')
        curr_pos = curr_pos + 2
        server_random = shelo[curr_pos:curr_pos + 32]
        curr_pos = curr_pos + 32
        legacy_sess_id_len = shelo[curr_pos]
        curr_pos = curr_pos + 1
        legacy_sess_id = shelo[curr_pos:curr_pos + legacy_sess_id_len]
        curr_pos = curr_pos + legacy_sess_id_len
        csuite = int.from_bytes(shelo[curr_pos:curr_pos + 2], 'big')
        curr_pos = curr_pos + 2
        self.csuite = csuite
        # SHOULD DOUBLE-CHECK HERE THAT CSUITE IS ONE THAT YOU SUPPORT
        legacy_compression = shelo[curr_pos]
        curr_pos = curr_pos + 1
        total_ext_len = int.from_bytes(shelo[curr_pos:curr_pos + 2], 'big')
        curr_pos = curr_pos + 2
        while curr_pos < msg_len:
            ext_type = int.from_bytes(shelo[curr_pos:curr_pos+2], 'big')
            curr_pos = curr_pos + 2
            ext_len = int.from_bytes(shelo[curr_pos:curr_pos+2], 'big')
            curr_pos = curr_pos + 2
            ext_bytes = shelo[curr_pos:curr_pos+ext_len]
            if ext_type == tls_constants.SUPPORT_VERS_TYPE:
                self.neg_version = int.from_bytes(ext_bytes, 'big')
            if ext_type == tls_constants.SUPPORT_GROUPS_TYPE:
                pass
            if ext_type == tls_constants.KEY_SHARE_TYPE:
                self.neg_group = int.from_bytes(ext_bytes[:2], 'big')
                keyshare_len = int.from_bytes(ext_bytes[2:4], 'big')
                legacy_form = ext_bytes[4]
                supported_keyshare = ext_bytes[5:]
                self.ec_pub_key = tls_crypto.convert_x_y_bytes_ec_pub(
                    supported_keyshare, self.neg_group)
            curr_pos = curr_pos + ext_len
        self.transcript = self.transcript + shelo_msg
        early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())
        ecdh_secret_point = tls_crypto.ec_dh(
            self.ec_sec_keys[self.neg_group], self.ec_pub_key)
        ecdh_secret = tls_crypto.point_to_secret(
            ecdh_secret_point, self.neg_group)
        handshake_secret = tls_crypto.tls_extract_secret(
            self.csuite, ecdh_secret, derived_early_secret)
        self.client_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "c hs traffic".encode(), self.transcript)
        self.server_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "s hs traffic".encode(), self.transcript)
        derived_hs_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "derived".encode(), "".encode())
        self.master_secret = tls_crypto.tls_extract_secret(
            self.csuite, None, derived_hs_secret)

        # with open('ut_tls_process_server_hello_int_inputs.txt', 'a') as handle:
        #     handle.write('\n%d %d %d %d %d\n' % (len(first_transcript),
        #                                          self.ec_sec_keys[tls_constants.SECP256R1_VALUE],
        #                                          self.ec_sec_keys[tls_constants.SECP384R1_VALUE],
        #                                          self.ec_sec_keys[tls_constants.SECP521R1_VALUE],
        #                                          len(shelo_msg)))
        # with open('ut_tls_process_server_hello_byte_inputs.txt', 'ab') as handle:
        #     handle.write(first_transcript + shelo_msg)
        # with open('ut_tls_process_server_hello_outputs.txt', 'a') as handle:
        #     handle.write('\n%s\n' % (self.transcript.hex() + self.csuite.to_bytes(2, 'big').hex()
        #                              + self.neg_version.to_bytes(2, 'big').hex()
        #                              + self.neg_group.to_bytes(2, 'big').hex()
        #                              + tls_crypto.convert_ec_pub_bytes(self.ec_pub_key,
        #                                                                self.neg_group).hex()
        #                              + self.local_hs_traffic_secret.hex()
        #                              + self.remote_hs_traffic_secret.hex()
        #                              + self.master_secret.hex()))
        return 0

    def tls_13_server_enc_ext(self):
        msg = 0x0000.to_bytes(2, 'big')
        enc_ext_msg = self.attach_handshake_header(
            tls_constants.ENEXT_TYPE, msg)
        self.transcript = self.transcript + enc_ext_msg
        return enc_ext_msg

    def tls_13_process_enc_ext(self, enc_ext_msg: bytes):
        enc_ext = self.process_handshake_header(
            tls_constants.ENEXT_TYPE, enc_ext_msg)
        if enc_ext != 0x0000.to_bytes(2, 'big'):
            raise InvalidMessageStructureError
        self.transcript = self.transcript + enc_ext_msg

    def tls_13_server_cert(self):
        certificate = tls_constants.SERVER_SUPPORTED_CERTIFICATES[self.signature]
        certificate_bytes = certificate.encode()
        cert_extensions = (0x0000).to_bytes(2, 'big')
        cert_len = (len(certificate_bytes) +
                    len(cert_extensions)).to_bytes(3, 'big')
        cert_chain_len = (len(certificate_bytes) +
                          len(cert_extensions) + len(cert_len)).to_bytes(3, 'big')
        cert_context_len = (0x00).to_bytes(1, 'big')
        msg = cert_context_len + cert_chain_len + \
            cert_len + certificate_bytes + cert_extensions
        cert_msg = self.attach_handshake_header(tls_constants.CERT_TYPE, msg)
        self.transcript = self.transcript + cert_msg
        return cert_msg

    def tls_13_process_server_cert(self, cert_msg: bytes):
        cert = self.process_handshake_header(tls_constants.CERT_TYPE, cert_msg)
        msg_len = len(cert)
        curr_pos = 0
        cert_context_len = cert[curr_pos]
        curr_pos = curr_pos + 1
        if cert_context_len != 0:
            cert_context = cert_msg[curr_pos:curr_pos + cert_context_len]
        curr_pos = curr_pos + cert_context_len
        while curr_pos < msg_len:
            cert_chain_len = int.from_bytes(
                cert[curr_pos: curr_pos + 3], 'big')
            curr_pos = curr_pos + 3
            cert_chain = cert[curr_pos:curr_pos+cert_chain_len]
            curr_chain_pos = 0
            while curr_chain_pos < cert_chain_len:
                cert_len = int.from_bytes(
                    cert_chain[curr_chain_pos: curr_chain_pos + 3], 'big')
                curr_chain_pos = curr_chain_pos + 3
                self.server_cert = cert_chain[curr_chain_pos:curr_chain_pos + cert_len - 2]
                self.server_cert_string = self.server_cert.decode('utf-8')
                # SUBTRACT TWO FOR THE EXTENSIONS, WHICH WILL ALWAYS BE EMPTY
                curr_chain_pos = curr_chain_pos + cert_len
            curr_pos = curr_pos + cert_chain_len
        self.transcript = self.transcript + cert_msg

    def tls_13_server_cert_verify(self) -> bytes:
        transcript_hash = tls_crypto.tls_transcript_hash(
            self.csuite, self.transcript)
        signature = tls_crypto.tls_signature(
            self.signature, transcript_hash, tls_constants.SERVER_FLAG)
        len_sig_bytes = len(signature).to_bytes(2, 'big')
        sig_type_bytes = self.signature.to_bytes(2, 'big')
        msg = sig_type_bytes + len_sig_bytes + signature
        cert_verify_msg = self.attach_handshake_header(
            tls_constants.CVFY_TYPE, msg)
        self.transcript = self.transcript + cert_verify_msg
        return cert_verify_msg

    def tls_13_process_server_cert_verify(self, verify_msg: bytes):
        #########################
        # THIS IS TO BE ASSESSED
        #########################
        first_transcript = self.transcript
        cert_verify = self.process_handshake_header(
            tls_constants.CVFY_TYPE, verify_msg)
        curr_pos = 0
        sig_type = int.from_bytes(cert_verify[curr_pos:curr_pos + 2], 'big')
        curr_pos = curr_pos + 2
        len_sig_bytes = int.from_bytes(
            cert_verify[curr_pos:curr_pos + 2], 'big')
        curr_pos = curr_pos + 2
        signature = cert_verify[curr_pos: curr_pos + len_sig_bytes]
        if ((sig_type == tls_constants.RSA_PKCS1_SHA256) or
                (sig_type == tls_constants.RSA_PKCS1_SHA384)):
            server_public_key = tls_crypto.get_rsa_pk_from_cert(
                self.server_cert_string)
        if sig_type == tls_constants.ECDSA_SECP384R1_SHA384:
            server_public_key = tls_crypto.get_ecdsa_pk_from_cert(
                self.server_cert_string)
        if sig_type == tls_constants.RING_SECP256K1_SHA256:
            server_public_key = tls_crypto.get_ring_pk_from_cert(
                self.server_cert_string)
        transcript_hash = tls_crypto.tls_transcript_hash(
            self.csuite, self.transcript)
        tls_crypto.tls_verify_signature(
            sig_type, transcript_hash, tls_constants.SERVER_FLAG, signature, server_public_key)
        self.transcript = self.transcript + verify_msg

        # with open('ut_tls_process_server_cert_verify_int_inputs.txt', 'a') as handle:
        #     handle.write('\n%d %d %d %d\n' % (self.csuite, len(self.server_cert_string.encode()),
        #                                       len(first_transcript),
        #                                       len(verify_msg)))
        # with open('ut_tls_process_server_cert_verify_byte_inputs.txt', 'ab') as handle:
        #     handle.write(self.server_cert_string.encode() +
        #                  first_transcript + verify_msg)
        # with open('ut_tls_process_server_cert_verify_outputs.txt', 'a') as handle:
        #     handle.write('\n%s\n' % (self.transcript.hex()))

    def tls_13_finished(self) -> bytes:
        transcript_hash = tls_crypto.tls_transcript_hash(
            self.csuite, self.transcript)
        finished_key = tls_crypto.tls_finished_key_derive(
            self.csuite, self.server_hs_traffic_secret)
        tag = tls_crypto.tls_finished_mac(
            self.csuite, finished_key, transcript_hash)
        fin_msg = self.attach_handshake_header(tls_constants.FINI_TYPE, tag)
        self.transcript = self.transcript + fin_msg
        if self.role == tls_constants.SERVER_FLAG:
            transcript_hash = tls_crypto.tls_transcript_hash(
                self.csuite, self.transcript)
            self.server_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "s ap traffic".encode(), transcript_hash)
            self.client_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "c ap traffic".encode(), transcript_hash)
        return fin_msg

    def tls_13_process_finished(self, fin_msg: bytes):
        #########################
        # THIS IS TO BE ASSESSED
        #########################
        # first_transcript = self.transcript
        finished = self.process_handshake_header(
            tls_constants.FINI_TYPE, fin_msg)
        msg_len = len(finished)
        curr_pos = 0
        remote_tag = finished[curr_pos:curr_pos+msg_len]
        transcript_hash = tls_crypto.tls_transcript_hash(
            self.csuite, self.transcript)
        finished_key = tls_crypto.tls_finished_key_derive(
            self.csuite, self.server_hs_traffic_secret)
        tls_crypto.tls_finished_mac_verify(
            self.csuite, finished_key, transcript_hash, remote_tag)
        self.transcript = self.transcript + fin_msg
        if self.role == tls_constants.CLIENT_FLAG:
            transcript_hash = tls_crypto.tls_transcript_hash(
                self.csuite, self.transcript)
            self.client_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "c ap traffic".encode(), transcript_hash)
            self.server_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "s ap traffic".encode(), transcript_hash)

        # with open('ut_tls_process_finished_int_inputs.txt', 'a') as handle:
        #     handle.write('\n%d %d %d %d %d\n' % (self.csuite, len(fin_msg), len(first_transcript),
        #                                          len(self.remote_hs_traffic_secret),
        #                                          len(self.master_secret)))
        # with open('ut_tls_process_finished_byte_inputs.txt', 'ab') as handle:
        #     handle.write(fin_msg + first_transcript + self.remote_hs_traffic_secret
        #                  + self.master_secret)
        # with open('ut_tls_process_finished_outputs.txt', 'a') as handle:
        #     handle.write('\n%s\n' % (self.transcript.hex()))
