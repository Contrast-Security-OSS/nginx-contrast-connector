# Building as a static module in nginx

These directions will not assume internet connectivity as part of the build
process.

Building this module as an nginx module is just like building most other nginx
modules. The general workflow is to download the nginx sources and module
sources, and use the nginx build system to reach out to the module sources to
build and include it in an nginx installation.

To start, there are two types of nginx modules: static or dynamic.  Static
module are compilied into the nginx binary and dynamic modules (while compiled
for a specific version of nginx) are selectively loaded into nginx at runtime.
These instructions will basically work for either. We are going to lean heavily
on the nginx documentation for this since modules use the nginx build system.

# Obtaining the source.

We target the latest stable release of nginx from its official source repo. At
the time of this writing, that is 1.14.0.  You can try with older versions of
nginx, but they are not being tested currently.

Here are some links to the source you will need:
* http://nginx.org/download/nginx-1.14.0.tar.gz
* https://github.com/protobuf-c/protobuf-c/releases/download/v1.3.1/protobuf-c-1.3.1.tar.gz
* XXX Insert link to CONTRAST NGINX CONNECTOR IN GITHUB XXX "contrast-webserver-agent-nginx-<version>.tgz"

# Setup

Unpack the three items to the same directory so they are adjacent to each
other.  It's not required to be adjacent, but it will make the example commands
using relative paths work out.

    tar -xzvf contrast-webserver-agent-nginx-1.0.0.tar.gz
    tar -xzvf nginx-1.14.0.tar.gz
    tar -xzvf protobuf-c-1.3.1.tar.gz

The connector module has an external dependency on protobuf-c which it will
link in statically to itself. It's not widely distributed to all distros that
we support so we are going to make a special compile of it just for this
project.  It's going to be "installed" to the directory 'protobuf-c-root'
alongside the other unpacked sources. The protobuf-c-root/ contents will only
be use during compilation. After compiling the contrast module here, the
protobuf-c-root/ dir is no longer needed and can be removed.

## Set up protobuf-c libs:

    cd protobuf-c-1.3.1
    ./configure CFLAGS="-fPIC" --disable-protoc --disable-shared --prefix=`pwd`/../protobuf-c-root
    make
    make install
    cd ..

Building this library with the -fPIC flag as above is important as it will be
statically linked into the contrast module dynamic object.

## build nginx + contrast module.

The nginx build system can build a dynamic nginx module or statically
compile the module into nginx. I'll first show the dynamic module compilation
step: 

    cd nginx-1.14.0
    PROTOBUFC_LIB=../protobuf-c-root/lib/ PROTOBUFC_INC=../protobuf-c-root/include/ \
        ./configure  --add-dynamic-module=../contrast-webserver-agent-nginx-1.0.0/ \
            --prefix=`pwd`/../nginx-svr --with-compat
    make
    make install
    cd ..

To compile nginx with the module statically compiled into it, you only need to
change one argument in the `./configure` step above. change the argument
`--add-dynamic-module=` to `--add-module=`.  Then proceed the same as above. It's
really that simple.

After building either the static or dynamic module, your entire nginx instance
along with all modules will be installed into the `nginx-svr/` dir adjacent to
the other unpacked project sources. Change the `--prefix` argument in the
`./configure` step above to put nginx in your desired location.

