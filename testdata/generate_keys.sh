#!/bin/bash

# Usage: bash generate-key.sh 8

num_denominations=$1

for i in $(eval echo {0..$(($num_denominations-1))})
do
    openssl ecparam -name prime256v1 -genkey -noout -out key$i.pem
done
