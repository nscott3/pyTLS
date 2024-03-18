#!/bin/bash

openssl req -new -sha384 -key secp384r1_privkey.pem -out secp384r1_sha_384_signreq.csr -subj "/C=CH/ST=Zurich/L=Zurich/O=ETH Interfocus Course/OU=IT/CN=www.example.com/emailAddress=benjamin.dowling@inf.ethz.ch"
openssl x509 -req -days 365 -in secp384r1_sha_384_signreq.csr -signkey secp384r1_privkey.pem -out secp384r1_sha_384_certificate.pem

openssl req -new -sha256 -key secp256k1_privkey.pem -out secp256k1_sha_256_signreq.csr -subj "/C=CH/ST=Zurich/L=Zurich/O=ETH Interfocus Course/OU=IT/CN=www.example.com/emailAddress=benjamin.dowling@inf.ethz.ch"
openssl x509 -req -days 365 -in secp256k1_sha_256_signreq.csr -signkey secp256k1_privkey.pem -out secp256k1_sha_256_certificate.pem