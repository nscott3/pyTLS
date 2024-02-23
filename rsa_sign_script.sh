#!/bin/bash

#openssl genrsa -out rsa_2048_privkey.pem 2048
openssl req -new -sha384 -key rsa_2048_privkey.pem -out rsa_2048_sha_384_signreq.csr -subj "/C=CH/ST=Zurich/L=Zurich/O=ETH Interfocus Course/OU=IT/CN=www.example.com/emailAddress=benjamin.dowling@inf.ethz.ch"
openssl x509 -req -days 365 -in rsa_2048_sha_384_signreq.csr -signkey rsa_2048_privkey.pem -out rsa_2048_sha_384_certificate.pem