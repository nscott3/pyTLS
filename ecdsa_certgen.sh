#!/bin/bash

openssl req -new -sha384 -key secp384r1_privkey.pem -out secp384r1_sha_384_signreq.csr -subj "/C=CH/ST=Zurich/L=Zurich/O=ETH Interfocus Course/OU=IT/CN=www.example.com/emailAddress=benjamin.dowling@inf.ethz.ch"
openssl x509 -req -days 365 -in secp384r1_sha_384_signreq.csr -signkey secp384r1_privkey.pem -out secp384r1_sha_384_certificate.pem