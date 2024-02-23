#!/usr/bin/env python

'''
simple_client.py:
Simple Client Socket using the TLS 1.3 Protocol
'''

import socket
from testing_client_server_consts import *
from tls_application import TLSConnection


def client_socket():
    s = socket.socket()
    host = socket.gethostname()
    #host = '18.216.1.168'
    s.connect((host, port))
    client = TLSConnection(s)
    client.connect(use_psk=True)
    client.write(msg1.encode())
    msg = client.read()
    print(msg.decode('utf-8'))
    psks = client.get_psks()
    s.close()
    s = socket.socket()
    s.connect((host, port))
    client = TLSConnection(s)
    client.connect(use_psk=True, psks=psks, psk_modes=[1],
                   early_data=ed.encode())
    client.write(msg2.encode())
    msg = client.read()
    print(msg.decode('utf-8'))
    s.close()


if __name__ == '__main__':
    client_socket()
