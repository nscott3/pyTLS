#!/usr/bin/bash

for i in {0..10}
do
    (./testing_server.py & ./testing_client.py ) >> test.out
done