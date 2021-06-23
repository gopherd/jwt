#!/bin/bash

set -e

target_dir=./testdata

openssl ecparam -genkey -name prime256v1 -out $target_dir/ec256.p1
openssl pkcs8 -in $target_dir/ec256.p1 -topk8 -out $target_dir/ec256.p8 -nocrypt
openssl ec -in $target_dir/ec256.p8 -pubout -out $target_dir/ec256.pub.p8
rm $target_dir/ec256.p1
