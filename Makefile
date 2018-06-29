
all: deps

deps: protobuf-c

clean-deps:
	rm -rf build/protobuf-c
	make -C submodules/protobuf-c clean

protobuf-c: 
	cd submodules/protobuf-c; ./autogen.sh
	cd submodules/protobuf-c; ./configure CFLAGS="-fPIC" --disable-protoc --disable-shared --prefix=`pwd`/../../build/protobuf-c
	make -C submodules/protobuf-c -j2
	make -C submodules/protobuf-c install
