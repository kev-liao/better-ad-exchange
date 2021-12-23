#!/bin/bash

# Usage: bash generate-key.sh 8

num_denominations=$1

for i in $(eval echo {0..$(($num_denominations-1))})
do
    openssl ecparam -name prime256v1 -genkey -noout -out key$i.pem
    go run ../crypto/generate_commitments_and_key.go -h2c_method swu -key key$i.pem -out key$i.comm    
done
