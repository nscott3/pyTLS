import tls_constants
import tls_crypto
from tls_handshake import *
from tls_psk_functions import *
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import Crypto.Random.random as random
from functools import reduce

FINISHED_SAMPLES = 15

PSK = PSKFunctions(None, None, None, None)
server_static_enc_key = get_random_bytes(ChaCha20_Poly1305.key_size)
resumption_secrets = []
csuites = []
nst_msgs = []
psk_dicts = []
with open('ut_tls_process_finished_int_inputs.txt', 'r') as filehandle:
    with open('ut_tls_process_finished_byte_inputs.txt', 'rb') as filehandletwo:
        curr_pos = 0
        finished_bytes = filehandletwo.read()
        for i in range(FINISHED_SAMPLES):
            line_space = filehandle.readline()
            finished_inp = filehandle.readline().split()
            csuite = int(finished_inp[0])
            len_fin = int(finished_inp[1])
            len_transcript = int(finished_inp[2])
            len_hs_secret = int(finished_inp[3])
            len_ms_secret = int(finished_inp[4])
            tmp_pos = curr_pos + len_fin
            fin_msg = finished_bytes[curr_pos:tmp_pos]
            curr_pos = tmp_pos
            tmp_pos = curr_pos + len_transcript
            transcript = finished_bytes[curr_pos:tmp_pos]
            curr_pos = tmp_pos
            tmp_pos = curr_pos + len_hs_secret
            hs_secret = finished_bytes[curr_pos:tmp_pos]
            curr_pos = tmp_pos
            tmp_pos = curr_pos + len_ms_secret
            ms_secret = finished_bytes[curr_pos:tmp_pos]
            curr_pos = tmp_pos
            resumption_secret = tls_crypto.tls_derive_secret(
                ms_secret, csuite, "res master".encode(), transcript)
            PSK.csuite = csuite
            resumption_secrets.append(resumption_secret)
            csuites.append(csuite)
            nst_msg = PSK.tls_13_server_new_session_ticket(
                server_static_enc_key, resumption_secret)
            nst_msgs.append(nst_msg)
            psk_dict = PSK.tls_13_client_parse_new_session_ticket(
                resumption_secret, nst_msg)
            psk_dicts.append(psk_dict)


with open('ut_tls_13_server_new_session_ticket_byte_inputs', 'wb') as byte_input:
    with open('ut_tls_13_server_new_session_ticket_int_inputs.txt', 'w') as int_input:
        with open('ut_tls_13_server_new_session_ticket_outputs', 'wb') as output:
            for (resumption_secret, csuite, nst_msg) in zip(resumption_secrets, csuites, nst_msgs):
                int_input.write(
                    f'\n{csuite} {len(server_static_enc_key)} {len(resumption_secret)}\n')
                byte_input.write(server_static_enc_key + resumption_secret)
                output.write(nst_msg)

with open('ut_tls_13_client_parse_new_session_ticket_byte_inputs', 'wb') as byte_input:
    with open('ut_tls_13_client_parse_new_session_ticket_int_inputs.txt', 'w') as int_input:
        with open('ut_tls_13_client_parse_new_session_ticket_byte_outputs', 'wb') as byte_output:
            with open('ut_tls_13_client_parse_new_session_ticket_int_outputs.txt', 'w') as int_output:
                for (resumption_secret, csuite, nst_msg, psk_dict) in zip(resumption_secrets, csuites, nst_msgs, psk_dicts):
                    int_input.write(
                        f'\n{csuite} {len(resumption_secret)} {len(nst_msg)}\n')
                    byte_input.write(resumption_secret + nst_msg)
                    byte_output.write(
                        psk_dict["PSK"] + psk_dict["ticket"] + psk_dict["binder key"])
                    int_output.write(
                        f'\n{len(psk_dict["PSK"])} {psk_dict["lifetime"]} {psk_dict["lifetime_add"]} {len(psk_dict["ticket"])} {psk_dict["max_data"]} {len(psk_dict["binder key"])} {psk_dict["csuite"]}\n')

PSKS_list = []
ticket_age_list = []
transcripts = []
psk_dicts_dict = {tls_constants.TLS_AES_128_GCM_SHA256: [
], tls_constants.TLS_AES_256_GCM_SHA384: [], tls_constants.TLS_CHACHA20_POLY1305_SHA256: []}
for psk_dict in psk_dicts:
    psk_dicts_dict[psk_dict['csuite']].append(psk_dict)

psk_csuites = []
for csuite in psk_dicts_dict:
    for _ in range(0, 5):
        psk_csuites.append(csuite)
        numPSK = random.randint(1, 5)
        PSKS = random.sample(psk_dicts_dict[csuite], numPSK)
        numValid = random.randint(1, numPSK)
        ticket_age = []
        for _ in range(0, numValid):
            ticket_age.append(random.randint(0, 604800*1000))
        for _ in range(0, numPSK-numValid):
            ticket_age.append(random.randint(604800*1000, 2**32-1))
        random.shuffle(ticket_age)
        PSKS_list.append(PSKS)
        ticket_age_list.append(ticket_age)
        transcripts.append(get_random_bytes(random.randint(200, 400)))

psk_extensions = []
with open('ut_tls_13_client_prep_psk_extension_byte_inputs', 'wb') as byte_input:
    with open('ut_tls_13_client_prep_psk_extension_int_inputs.txt', 'w') as int_input:
        with open('ut_tls_13_client_prep_psk_extension_byte_outputs', 'wb') as byte_output:
            with open('ut_tls_13_client_prep_psk_extension_int_outputs.txt', 'w') as int_output:
                for (csuite, psks, ticket_age, transcript) in zip(psk_csuites, PSKS_list, ticket_age_list, transcripts):
                    int_input.write(f'\n{csuite} {len(transcript)} {len(psks)}\n')
                    byte_input.write(transcript)
                    for psk_dict, age in zip(psks, ticket_age):
                        int_input.write(
                            f'{len(psk_dict["PSK"])} {psk_dict["lifetime"]} {psk_dict["lifetime_add"]} {len(psk_dict["ticket"])} {psk_dict["max_data"]} {len(psk_dict["binder key"])} {psk_dict["csuite"]} {age}\n')
                        byte_input.write(psk_dict["PSK"] + psk_dict["ticket"] + psk_dict["binder key"])
                    PSK.csuite = csuite
                    psk_extension = PSK.tls_13_client_prep_psk_extension(
                        psks, ticket_age, transcript)
                    
                    psk_extensions.append(psk_extension)
                    byte_output.write(psk_extension)
                    int_output.write(f'\n{len(psk_extension)}\n')


with open('ut_tls_13_server_parse_psk_extension_byte_inputs', 'wb') as byte_input:
    with open('ut_tls_13_server_parse_psk_extension_int_inputs.txt', 'w') as int_input:
        with open('ut_tls_13_server_parse_psk_extension_byte_outputs', 'wb') as byte_output:
            with open('ut_tls_13_server_parse_psk_extension_int_outputs.txt', 'w') as int_output:
                for (csuite, psk_extension, transcript) in zip(psk_csuites, psk_extensions, transcripts):
                    int_input.write(
                        f'\n{csuite} {len(psk_extension)} {len(transcript)} {len(server_static_enc_key)}\n')
                    byte_input.write(psk_extension + transcript + server_static_enc_key)
                    PSK.csuite = csuite
                    psk, selected_identity = PSK.tls_13_server_parse_psk_extension(
                        server_static_enc_key, psk_extension, transcript)
                    int_output.write(f'\n{len(psk)} {selected_identity}\n')
                    byte_output.write(psk)
