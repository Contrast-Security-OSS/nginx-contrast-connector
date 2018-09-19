#!/bin/bash
ver=1.3.1
name=protobuf-c-$ver

mkdir -p /tmp/protobuf-build
pushd /tmp/protobuf-build
curl -L https://github.com/protobuf-c/protobuf-c/releases/download/v$ver/$name.tar.gz \
    -o $name.tar.gz
tar -xzvf $name.tar.gz
pushd $name
./configure CFLAGS="-fPIC" --disable-protoc --disable-shared --prefix=/usr/local/protobuf-c
make
make install

popd
popd
