#!/usr/bin/env python

'''
tls_psk_handshake.py:
A series of functions implementing aspects of TLS 1.3 PSK functionality
'''

import pickle
from io import open
import time
from typing import Dict, List, Tuple, Union
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Hash import HMAC, SHA256, SHA384
from Cryptodome.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions
from tls_handshake import Handshake

generate_client_test = False
generate_server_test = False
generate_server_random_test = False


def timer() -> int:
    return int(time.time()*1000)


class PSKHandshake(Handshake):
    "This is the class for aspects of the handshake protocol"

    __rand_id = 0

    def __init__(self, csuites: List[int], extensions: Dict[int, List[int]], role: int,
                 psks: List[Dict[str, Union[bytes, int]]] = None, psk_modes: List[int] = None,
                 server_static_enc_key: bytes = None, early_data: bytes = None):
        super().__init__(csuites, extensions, role)
        self.psks = psks
        self.psk = None
        self.psk_modes = psk_modes
        self.server_static_enc_key = server_static_enc_key
        self.early_data = early_data
        self.client_early_traffic_secret = None
        self.accept_early_data = False
        self.selected_identity = None
        self.resumption_master_secret = None
        self.max_early_data = None
        self.offered_psks = None
        self.use_keyshare = None
        self.client_early_data = None
        self.get_time = timer
        self.get_random_bytes = get_random_bytes

    def tls_13_server_new_session_ticket(self) -> bytes:
        #########################
        # THIS IS TO BE ASSESSED
        #########################
        # ticket_lifetime = maximum lifetime = 604800 seconds
        # ticket_add_age = 32-bit random nonce, used to hide ticket age in PSK extensions
        # ticket_nonce = 64-bit random nonce, used to generate the PSK
        # Generate the PSK using the resumption secret + nonce
        # HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
        # Generate a random 64-bit nonce for encryption
        # ticket = encryption using master_key PSK, ticket_add_age, ticket_lifetime
        # append the nonce at the front of the ciphertext
        # ExtensionType = uint8 early_data(42)
        # max_early_data_size = 2^12 in uint32
        # Extension length encoding = uint16
        # ticket_length_encoding = uint16
        # ticket_nonce_length_encoding = unit16
        # HandshakeMessageType = NewSessionTicket - CAN USE ATTACH HANDSHAKE HEADER FOR THIS
        # new_session_ticket_length_encoding = uint24  - CAN USE ATTACH HANDSHAKE HEADER FOR THIS
        # self.get_random_bytes = randbytes
        # seed("test_tls_13_server_new_session_ticket")
        if generate_server_random_test:
            self.rand_id = PSKHandshake.__rand_id
            PSKHandshake.__rand_id = (PSKHandshake.__rand_id + 1) % 256
            with open('ut_tls_13_server_new_session_ticket.txt', mode='a', newline='\n') as handle:
                handle.write('%s\n' % (pickle.dumps(self).hex()))
            self.get_random_bytes = lambda n: self.rand_id.to_bytes(n, 'big')
        csuite = self.csuite
        resumption_secret = self.resumption_master_secret
        server_static_enc_key = self.server_static_enc_key
        hkdf = tls_crypto.HKDF(csuite)

        ticket_lifetime = 604800
        ticket_lifetime_bytes = ticket_lifetime.to_bytes(4, 'big')
        ticket_add_age = self.get_random_bytes(4)
        ticket_nonce = self.get_random_bytes(8)
        psk = hkdf.tls_hkdf_expand(resumption_secret, tls_crypto.tls_hkdf_label(
            "resumption".encode(), ticket_nonce, hkdf.hash_length), hkdf.hash_length)

        nonce = self.get_random_bytes(8)
        cipher = ChaCha20_Poly1305.new(key=server_static_enc_key, nonce=nonce)
        plaintext = psk + ticket_add_age + \
            ticket_lifetime_bytes + csuite.to_bytes(2, 'big')
        ctxt, tag = cipher.encrypt_and_digest(plaintext)
        ticket = nonce + ctxt + tag

        extension_type = tls_constants.EARLY_DATA_TYPE.to_bytes(2, 'big')
        max_early_data_size = 2**12
        max_early_data_size_bytes = max_early_data_size.to_bytes(4, 'big')
        max_early_data_size_len = len(
            max_early_data_size_bytes).to_bytes(2, 'big')
        extensions = extension_type + max_early_data_size_len + max_early_data_size_bytes
        exten_len = len(extensions).to_bytes(2, 'big')
        ticket_len = len(ticket).to_bytes(2, 'big')
        ticket_nonce_len = len(ticket_nonce).to_bytes(1, 'big')

        nst = ticket_lifetime_bytes + ticket_add_age + ticket_nonce_len + \
            ticket_nonce + ticket_len + ticket + exten_len + extensions

        msg = self.attach_handshake_header(tls_constants.NEWST_TYPE, nst)

        if generate_server_random_test:
            with open('ut_tls_13_server_new_session_ticket_out.txt', mode='a', newline='\n') as handle:
                handle.write('%s\n' % (msg.hex()))
            self.get_random_bytes = get_random_bytes
        return msg

    def tls_13_client_parse_new_session_ticket(self, nst_msg: bytes) -> Dict[str, Union[bytes, int]]:
        #########################
        # THIS IS TO BE ASSESSED
        #########################
        # create a dictionary called PSK
        # parse lifetime from NewSessionTicket
        # parse ticket_add_age from NewSessionTicket
        # parse nonce from NewSessionTicket
        # parse ticket from NewSessionTicket
        # parse max_data from EarlyDataIndication extension
        # Generate the PSK using the resumption secret + nonce
        # HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
        # Generate the binder key using the PSK
        # ES = HKDF-Extract(0,PSK)
        # binder_key = Derive-Secret(ES, "res binder".encode(), "")

        # save "PSK": PSK, "lifetime": lifetime, "lifetime_add": lifetime add, "ticket": ticket,
        # "max_data":max_data, "binder key": binder_key, "csuite": csuite to PSK dictionary
        # return PSK dictionary
        arrival = self.get_time()
        if generate_client_test:
            with open('ut_tls_13_client_parse_new_session_ticket.txt', mode='a', newline='\n') as handle:
                handle.write('%s\n%s\n%d\n' %
                             (pickle.dumps(self).hex(), nst_msg.hex(), arrival))
        nst_msg = self.process_handshake_header(
            tls_constants.NEWST_TYPE, nst_msg)
        resumption_secret = self.resumption_master_secret
        curr_pos = 0
        ticket_lifetime = int.from_bytes(nst_msg[curr_pos:curr_pos+4], 'big')
        curr_pos += 4
        ticket_add_age = int.from_bytes(nst_msg[curr_pos:curr_pos+4], 'big')
        curr_pos += 4
        ticket_nonce_len = int.from_bytes(nst_msg[curr_pos:curr_pos+1], 'big')
        curr_pos += 1
        ticket_nonce = nst_msg[curr_pos:curr_pos+ticket_nonce_len]
        curr_pos += ticket_nonce_len
        ticket_len = int.from_bytes(nst_msg[curr_pos:curr_pos+2], 'big')
        curr_pos += 2
        ticket = nst_msg[curr_pos:curr_pos+ticket_len]
        curr_pos = curr_pos + ticket_len
        exten_len = int.from_bytes(nst_msg[curr_pos:curr_pos+2], 'big')
        curr_pos = curr_pos+2
        extensions = nst_msg[curr_pos:curr_pos+exten_len]
        curr_pos += exten_len
        if curr_pos != len(nst_msg):
            raise InvalidMessageStructureError()
        extension_type = int.from_bytes(extensions[:2], 'big')
        extension_data_len = int.from_bytes(extensions[2:4], 'big')
        if extension_type != tls_constants.EARLY_DATA_TYPE:
            raise InvalidMessageStructureError()
        max_data = int.from_bytes(extensions[4:4+extension_data_len], 'big')
        hkdf = tls_crypto.HKDF(self.csuite)
        psk = hkdf.tls_hkdf_expand(resumption_secret, tls_crypto.tls_hkdf_label(
            "resumption".encode(), ticket_nonce, hkdf.hash_length), hkdf.hash_length)
        early_secret = tls_crypto.tls_extract_secret(self.csuite, psk, None)
        binder_key = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "res binder".encode(), "".encode())

        psk_dict = {"PSK": psk, "lifetime": ticket_lifetime, "lifetime_add": ticket_add_age,
                    "ticket": ticket, "max_data": max_data, "binder key": binder_key,
                    "csuite": self.csuite, "arrival": arrival}

        if generate_client_test:
            with open('ut_tls_13_client_parse_new_session_ticket_out.txt', mode='a',
                      newline='\n') as handle:
                handle.write('%s\n' % (pickle.dumps(psk_dict).hex()))
        return psk_dict

    def tls_13_client_prep_psk_mode_extension(self) -> bytes:
        #########################
        # THIS IS TO BE ASSESSED
        #########################

        if generate_client_test:
            with open('ut_tls_13_client_prep_psk_mode_extension.txt', mode='a', newline='\n') as handle:
                handle.write('%s\n' % (pickle.dumps(self).hex()))
        modes = self.psk_modes
        psk_modes = "".encode()
        for mode in modes:
            psk_modes = psk_modes + mode.to_bytes(1, 'big')
        psk_mode_type = tls_constants.PSK_KEX_MODE_TYPE.to_bytes(2, 'big')
        len_encode = (len(psk_modes)).to_bytes(1, 'big')
        psk_key_exchange_modes = len_encode + psk_modes
        psk_key_exchange_modes_len = len(
            psk_key_exchange_modes).to_bytes(2, 'big')
        psk_mode_ext = psk_mode_type + psk_key_exchange_modes_len + psk_key_exchange_modes

        if generate_client_test:
            with open('ut_tls_13_client_prep_psk_mode_extension_out.txt', mode='a',
                      newline='\n') as handle:
                handle.write('%s\n' % (psk_mode_ext.hex()))
        return psk_mode_ext

    def tls_13_client_add_psk_extension(self, chelo: bytes, extensions: bytes) -> Tuple[bytes, List[Dict[str, Union[bytes, int]]]]:
        #########################
        # THIS IS TO BE ASSESSED
        # #########################
        if generate_client_test:
            with open('ut_tls_13_client_add_psk_extension.txt', mode='a', newline='\n') as handle:
                handle.write('%s\n%s\n%s\n' % (pickle.dumps(
                    self).hex(), chelo.hex(), extensions.hex()))
        # Prepare the list of PSK Identities
        # This is a list of all tickets contained in each PSK in PSKS
        list_psk_identities = "".encode()
        msg_len = 0
        psks = self.psks
        now = self.get_time()
        if generate_client_test:
            with open('ut_tls_13_client_add_psk_extension.txt', mode='a', newline='\n') as handle:
                handle.write('%d\n' % (now))
        psks_offered = []
        for psk in psks:
            psk_ticket = psk["ticket"]
            len_encode_ticket = len(psk_ticket).to_bytes(2, 'big')
            psk_age = now-psk["arrival"]
            obsfucated_ticket_age = (
                (psk_age + psk["lifetime_add"]) % 2**32).to_bytes(4, 'big')
            psk_lifetime = psk["lifetime"]
            psk_identity = len_encode_ticket + psk_ticket + obsfucated_ticket_age
            if psk_age < psk_lifetime*1000:
                list_psk_identities = list_psk_identities + psk_identity
                psks_offered.append(psk)
        len_encode_identities = len(list_psk_identities).to_bytes(2, 'big')
        ext_identities = len_encode_identities + list_psk_identities
        msg_len = msg_len + len(ext_identities)
        for psk in psks:
            psk_age = now-psk["arrival"]
            psk_lifetime = psk["lifetime"]
            binders_length = 0
            if psk_age < psk_lifetime*1000:
                if psk["csuite"] in [tls_constants.TLS_AES_128_GCM_SHA256,
                                     tls_constants.TLS_CHACHA20_POLY1305_SHA256]:
                    hash = SHA256.new()
                if psk["csuite"] == tls_constants.TLS_AES_256_GCM_SHA384:
                    hash = SHA384.new()
                hash_length = hash.digest_size
                binder_length = hash_length
                binder_entry_length = binder_length + 1
                msg_len = msg_len + binder_entry_length
                binders_length = binders_length + binder_entry_length
        msg_len = msg_len + 2  # For the length encoding of the PskBinderEntry struct
        ext_type = tls_constants.PSK_TYPE.to_bytes(2, 'big')
        binder_msg_in = ext_type + msg_len.to_bytes(2, 'big') + ext_identities
        msg_len += 2+2  # 2 bytes for ext_type, 2 bytes for msg_len
        ext = extensions + binder_msg_in
        ext_len = len(extensions) + msg_len
        chelo_len = len(chelo)
        len_msg = (chelo_len + ext_len + 2).to_bytes(3, 'big')
        hs_msg_type = tls_constants.CHELO_TYPE.to_bytes(1, 'big')
        transcript = hs_msg_type + len_msg + \
            chelo + ext_len.to_bytes(2, 'big') + ext
        ext_binders = "".encode()
        for psk in psks:
            psk_age = now-psk["arrival"]
            psk_lifetime = psk["lifetime"]
            if psk_age < psk_lifetime*1000:
                finished_key = tls_crypto.tls_finished_key_derive(
                    psk["csuite"], psk["binder key"])
                transcript_hash = tls_crypto.tls_transcript_hash(
                    psk["csuite"], transcript)
                binder = tls_crypto.tls_finished_mac(
                    psk["csuite"], finished_key, transcript_hash)
                binder_entry = len(binder).to_bytes(1, 'big') + binder
                ext_binders = ext_binders + binder_entry
        ext_binders = len(ext_binders).to_bytes(2, 'big') + ext_binders
        psk_msg = ext_identities + ext_binders
        psk_msg_len = len(psk_msg).to_bytes(2, 'big')
        preshared_key_extension = ext_type + psk_msg_len + psk_msg

        if generate_client_test:
            with open('ut_tls_13_client_add_psk_extension_out.txt', mode='a', newline='\n') as handle:
                handle.write('%s\n%s\n' % (preshared_key_extension.hex(),
                                           pickle.dumps(psks_offered).hex()))
        return preshared_key_extension, psks_offered

    def tls_13_server_parse_psk_extension(self, psk_extension: bytes) -> Tuple[bytes, int]:
        #########################
        # THIS IS TO BE ASSESSED
        #########################
        if generate_server_test:
            with open('ut_tls_13_server_parse_psk_extension.txt', mode='a', newline='\n') as handle:
                handle.write('%s\n%s\n' %
                             (pickle.dumps(self).hex(), psk_extension.hex()))
        # Server should, for each PSK, decrypt the ticket
        # recover the PSK, ticket_lifetime, ticket_add_age
        # compare ticket_lifetime to de-obsfucated ticket_age
        # if ticket_lifetime < ticket_age, move onto the next PSK
        # if not, compute the binder value by:
        # computing the binder key from PSK
        # truncating the  psk_extension: the truncation should drop the psk_binders part of
        # the psk_extension, including the length fields for those parts
        # concatenating the truncation with the transcript given as input (a fake client hello)
        # compute the transcript hash by using tls_crypto.transcript_hash
        # compute the hmac over the transcript hash
        # if the binder value matches the hmac output, the server should return PSK
        server_static_enc_key = self.server_static_enc_key
        identities_len = int.from_bytes(psk_extension[:2], 'big')
        if identities_len < 7:
            raise InvalidMessageStructureError
        cur_pos = 2
        identities = psk_extension[cur_pos:cur_pos+identities_len]
        cur_pos += identities_len
        binders_len = int.from_bytes(psk_extension[cur_pos:cur_pos+2], 'big')
        if binders_len < 33:
            raise InvalidMessageStructureError
        cur_pos += 2
        binders = psk_extension[cur_pos:cur_pos+binders_len]
        if len(psk_extension) != 2 + identities_len + 2 + binders_len:
            raise InvalidMessageStructureError

        selected_identity = 0
        ids_pos = 0
        binders_pos = 0

        binder_msg_in = self.transcript[:-binders_len-2]

        while ids_pos < identities_len and binders_pos < binders_len:
            id_len = int.from_bytes(identities[ids_pos:ids_pos+2], 'big')
            ids_pos += 2

            if id_len + 4 + ids_pos > identities_len:
                raise InvalidMessageStructureError()

            ticket = identities[ids_pos:ids_pos+id_len]
            ids_pos += id_len
            obfuscated_ticket_age = identities[ids_pos:ids_pos+4]
            obfuscated_ticket_age = int.from_bytes(
                obfuscated_ticket_age, 'big')
            ids_pos += 4

            nonce = ticket[:8]
            ciphertext = ticket[8:]
            cipher = ChaCha20_Poly1305.new(
                key=server_static_enc_key, nonce=nonce)
            aead_ctxt_len = len(ciphertext)
            mac_len = tls_constants.MAC_LEN[tls_constants.TLS_CHACHA20_POLY1305_SHA256]
            ctxt_len = aead_ctxt_len - mac_len
            ctxt = ciphertext[:ctxt_len]
            tag = ciphertext[ctxt_len:]
            plaintext = cipher.decrypt_and_verify(ctxt, tag)

            psk_len = len(plaintext) - 10
            psk = plaintext[:psk_len]
            ticket_add_age = int.from_bytes(
                plaintext[psk_len:psk_len+4], 'big')
            ticket_lifetime = int.from_bytes(
                plaintext[psk_len+4:psk_len+8], 'big')
            ticket_csuite = int.from_bytes(
                plaintext[psk_len+8:psk_len+10], 'big')
            ticket_age = (obfuscated_ticket_age - ticket_add_age) % 2**32

            binder_len = int.from_bytes(
                binders[binders_pos:binders_pos+1], 'big')
            binders_pos += 1
            binder = binders[binders_pos:binders_pos+binder_len]
            binders_pos += binder_len
            if self.csuite == ticket_csuite and ticket_age < (ticket_lifetime * 1000):
                early_secret = tls_crypto.tls_extract_secret(
                    self.csuite, psk, None)

                binder_key = tls_crypto.tls_derive_secret(
                    self.csuite, early_secret, "res binder".encode(), "".encode())
                transcript_hash = tls_crypto.tls_transcript_hash(
                    self.csuite, binder_msg_in)
                finished_key = tls_crypto.tls_finished_key_derive(
                    self.csuite, binder_key)
                tag = tls_crypto.tls_finished_mac(
                    self.csuite, finished_key, transcript_hash)
                if binder == tag:
                    if generate_server_test:
                        with open('ut_tls_13_server_parse_psk_extension_out.txt', mode='a', newline='\n') as handle:
                            handle.write('%s\n%d\n' %
                                         (psk.hex(), selected_identity))
                    return psk, selected_identity
                else:
                    raise BinderVerificationError()
            selected_identity += 1
        raise TLSError()

    def tls_13_client_hello(self) -> bytes:
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

        chelo_msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + \
            csuites_len + csuites_bytes + comp_len + legacy_compression
        if self.psks:
            if not self.early_data is None:
                extensions += self.tls_13_early_data_ext()
            psk_mode_ext = self.tls_13_client_prep_psk_mode_extension()
            extensions += psk_mode_ext
            psk_ext, psks_offered = self.tls_13_client_add_psk_extension(
                chelo_msg, extensions)
            extensions += psk_ext
            if not self.early_data is None:
                self.max_early_data = psks_offered[0]['max_data']
                self.csuite = psks_offered[0]['csuite']
                self.offered_psks = psks_offered

        exten_len = len(extensions).to_bytes(2, 'big')
        # WE CAN NOW CONSTRUCT OUR CLIENTHELLO MESSAGE
        chelo_msg += exten_len + extensions
        # AND CREATE OUR TLS CLIENTHELLO HANDSHAKE HEADER
        client_hello_msg = self.attach_handshake_header(
            tls_constants.CHELO_TYPE, chelo_msg)
        # UPDATE STATE SO OUR IMPLEMENTATION DOESN'T LOSE
        # WHERE IT CURRENTLY IS IN STATE
        self.state = tls_constants.CCHELO_STATE
        self.chelo = client_hello_msg
        self.transcript = self.transcript + client_hello_msg
        if self.psks and not self.early_data is None:
            early_secret = tls_crypto.tls_extract_secret(
                psks_offered[0]['csuite'], psks_offered[0]['PSK'], None)
            self.client_early_traffic_secret = tls_crypto.tls_derive_secret(
                psks_offered[0]['csuite'], early_secret, "c e traffic".encode(), self.transcript)

        return client_hello_msg

    def tls_13_compute_client_early_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.client_early_traffic_secret is None:
            raise StateConfusionError()
        early_data_key, early_data_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_early_traffic_secret)
        return early_data_key, early_data_iv, self.csuite

    def tls_13_eoed(self) -> bytes:
        return self.attach_handshake_header(tls_constants.EOED_TYPE, b'')

    def tls_13_finished(self) -> bytes:
        fin_msg = super().tls_13_finished()
        if not self.psks is None:
            if self.role == tls_constants.SERVER_FLAG:
                transcript_hash = tls_crypto.tls_transcript_hash(
                    self.csuite, self.transcript)
                self.resumption_master_secret = tls_crypto.tls_derive_secret(
                    self.csuite, self.master_secret, "res master".encode(), transcript_hash)
        return fin_msg

    def tls_13_process_finished(self, fin_msg: bytes):
        super().tls_13_process_finished(fin_msg)
        if not self.psks is None:
            if (self.role == tls_constants.CLIENT_FLAG):
                transcript_hash = tls_crypto.tls_transcript_hash(
                    self.csuite, self.transcript)
                self.resumption_master_secret = tls_crypto.tls_derive_secret(
                    self.csuite, self.master_secret, "res master".encode(), transcript_hash)

    def tls_13_early_data_ext(self, data: bytes = b'') -> bytes:
        early_data_len = len(data)
        early_data_ext = tls_constants.EARLY_DATA_TYPE.to_bytes(
            2, 'big') + early_data_len.to_bytes(tls_constants.EXT_LEN_LEN, 'big') + data
        return early_data_ext

    def tls_13_server_enc_ext(self) -> bytes:
        msg = b''
        if self.accept_early_data:
            msg += self.tls_13_early_data_ext()
        msg_len = len(msg).to_bytes(2, 'big')
        msg = msg_len + msg
        enc_ext_msg = self.attach_handshake_header(
            tls_constants.ENEXT_TYPE, msg)
        self.transcript = self.transcript + enc_ext_msg
        return enc_ext_msg

    def tls_13_process_enc_ext(self, enc_ext_msg: bytes):
        enc_ext = self.process_handshake_header(
            tls_constants.ENEXT_TYPE, enc_ext_msg)
        extensions_len = int.from_bytes(enc_ext[0:2], 'big')
        extensions = enc_ext[2:2+extensions_len]
        if extensions_len > 0:
            ext_type = int.from_bytes(extensions[0:2], 'big')
            ext_data_len = int.from_bytes(extensions[2:4], 'big')
            ext_data = extensions[4:]
            if ext_type != tls_constants.EARLY_DATA_TYPE or ext_data_len != 0 or ext_data != b'':
                raise InvalidMessageStructureError
            self.accept_early_data = True
        self.transcript = self.transcript + enc_ext_msg

    def tls_13_server_get_remote_extensions(self) -> Dict[str, bytes]:
        remote_extensions = super().tls_13_server_get_remote_extensions()
        curr_ext_pos = 0
        while curr_ext_pos < len(self.remote_extensions):
            ext_type = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_len = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_bytes = self.remote_extensions[curr_ext_pos:curr_ext_pos+ext_len]
            if ext_type == tls_constants.PSK_TYPE:
                remote_extensions['psk'] = ext_bytes
            if ext_type == tls_constants.PSK_KEX_MODE_TYPE:
                remote_extensions['psk mode'] = ext_bytes
            if ext_type == tls_constants.EARLY_DATA_TYPE:
                remote_extensions['early data'] = ext_bytes
            curr_ext_pos = curr_ext_pos + ext_len
        return remote_extensions

    def tls_13_server_parse_psk_mode_ext(self, modes_bytes: bytes) -> bytes:
        modes_len = modes_bytes[0]
        modes = modes_bytes[1:modes_len+1]
        return modes

    def tls_13_server_select_parameters(self, remote_extensions: Dict[str, bytes]):
        self.use_keyshare = True
        self.client_early_data = False

        self.neg_version = tls_extensions.negotiate_support_vers_ext(
            self.extensions, remote_extensions['supported versions'])
        self.csuite = tls_extensions.negotiate_support_csuite(
            self.csuites, self.num_remote_csuites, self.remote_csuites)
        if 'psk' in remote_extensions and 'psk mode' in remote_extensions:
            modes = self.tls_13_server_parse_psk_mode_ext(
                remote_extensions['psk mode'])
            self.psk, self.selected_identity = self.tls_13_server_parse_psk_extension(
                remote_extensions['psk'])
            self.use_keyshare = tls_constants.PSK_DHE_KE_MODE.to_bytes(
                1, 'big') in modes
            if 'early data' in remote_extensions:
                self.client_early_data = True
                self.accept_early_data = self.selected_identity == 0
        if self.use_keyshare:
            self.neg_group = tls_extensions.negotiate_support_group_ext(
                self.extensions, remote_extensions['supported groups'])
            (self.pub_key, self.neg_group, self.ec_pub_key,
             self.ec_sec_key) = tls_extensions.negotiate_keyshare(
                self.extensions, self.neg_group, remote_extensions['key share'])
            self.signature = tls_extensions.negotiate_signature_ext(
                self.extensions, remote_extensions['sig algs'])

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
        # neg_group_ext = tls_extensions.finish_support_group_ext(self.neg_group)
        # + neg_group_ext  We do not need to send a supported group extension
        extensions = neg_vers_ext
        if self.use_keyshare:
            supported_keyshare = tls_extensions.finish_keyshare_ext(
                self.pub_key, self.neg_group)
            extensions += supported_keyshare
            ecdh_secret_point = tls_crypto.ec_dh(
                self.ec_sec_key, self.ec_pub_key)
            ecdh_secret = tls_crypto.point_to_secret(
                ecdh_secret_point, self.neg_group)
        else:
            ecdh_secret = None
        if not self.psk is None:
            psk_ext = tls_constants.PSK_TYPE.to_bytes(2, 'big') + tls_constants.SEL_ID_LEN.to_bytes(
                2, 'big') + self.selected_identity.to_bytes(tls_constants.SEL_ID_LEN, 'big')
            extensions += psk_ext
        exten_len = len(extensions).to_bytes(2, 'big')
        msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + \
            csuite_bytes + legacy_compression + exten_len + extensions
        shelo_msg = self.attach_handshake_header(tls_constants.SHELO_TYPE, msg)

        early_secret = tls_crypto.tls_extract_secret(
            self.csuite, self.psk, None)
        self.client_early_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, b'c e traffic', self.transcript)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())

        self.transcript += shelo_msg
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
        # first_transcript = self.transcript
        self.psk = None
        supported_keyshare = None
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
                # self.neg_group = int.from_bytes(ext_bytes, 'big')
                pass
            if ext_type == tls_constants.KEY_SHARE_TYPE:
                self.neg_group = int.from_bytes(ext_bytes[:2], 'big')
                keyshare_len = int.from_bytes(ext_bytes[2:4], 'big')
                legacy_form = ext_bytes[4]
                supported_keyshare = ext_bytes[5:]
                self.ec_pub_key = tls_crypto.convert_x_y_bytes_ec_pub(
                    supported_keyshare, self.neg_group)
            if ext_type == tls_constants.PSK_TYPE:
                self.selected_identity = int.from_bytes(ext_bytes[:2], 'big')
                psk = self.psks[self.selected_identity]
                if psk['csuite'] != csuite:
                    raise InvalidMessageStructureError()
                self.psk = psk["PSK"]
            curr_pos = curr_pos + ext_len

        if (tls_constants.PSK_DHE_KE_MODE in self.psk_modes and
                not tls_constants.PSK_KE_MODE in self.psk_modes):
            if supported_keyshare is None:
                raise InvalidMessageStructureError()

        self.transcript = self.transcript + shelo_msg
        early_secret = tls_crypto.tls_extract_secret(
            self.csuite, self.psk, None)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())
        if not supported_keyshare is None:
            ecdh_secret_point = tls_crypto.ec_dh(
                self.ec_sec_keys[self.neg_group], self.ec_pub_key)
            ecdh_secret = tls_crypto.point_to_secret(
                ecdh_secret_point, self.neg_group)
        else:
            ecdh_secret = None
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
