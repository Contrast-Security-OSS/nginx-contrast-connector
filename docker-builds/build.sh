#!/bin/sh

set -ex

#make modsecurity
#cd /usr/src/
#git clone https://github.com/SpiderLabs/ModSecurity.git /usr/src/modsecurity
#cd /usr/src/modsecurity
# we need master as the last release, v3.0.2, contains a bug in storing IP
# collections.
#git checkout v3/master
#git submodule update --init --recursive
#autoreconf -fiv
#./configure --enable-parser-generation
#make -j6
#make install

cd /nginx-speedracer-connector
make dist
CONN_VERSION=`cat VERSION`
cd /
tar -xzf nginx-speedracer-connector/contrast-webserver-agent-nginx-$CONN_VERSION.tgz

cd /
curl -L -o /nginx-1.14.1.tar.gz http://nginx.org/download/nginx-1.14.1.tar.gz
curl -L https://github.com/protobuf-c/protobuf-c/releases/download/v1.3.1/protobuf-c-1.3.1.tar.gz > protobuf-c-1.3.1.tar.gz

tar -xzf /nginx-1.14.1.tar.gz
tar -xzf /protobuf-c-1.3.1.tar.gz

# protobuf-c
cd protobuf-c-1.3.1
./configure CFLAGS="-fPIC" --disable-protoc --disable-shared --prefix=`pwd`/../protobuf-c-root
make -j4
make install
cd /
ls -l /
# nginx + module
cd nginx-1.14.1
PROTOBUFC_LIB=../protobuf-c-root/lib/ PROTOBUFC_INC=../protobuf-c-root/include/ \
    ./configure \
    --add-dynamic-module=../contrast-webserver-agent-nginx-$CONN_VERSION \
                 --with-compat \
                 --with-http_ssl_module --without-http_access_module \
                 --without-http_auth_basic_module \
                 --without-http_autoindex_module \
                 --without-http_empty_gif_module \
                 --without-http_fastcgi_module \
                 --without-http_referer_module \
                 --without-http_memcached_module \
                 --without-http_scgi_module \
                 --without-http_split_clients_module \
                 --without-http_ssi_module \
                 --without-http_uwsgi_module
make -j4 install

# now make the contrast-service

curl -o /go1.11.tgz https://dl.google.com/go/go1.11.linux-amd64.tar.gz
tar -C /usr/local -xzf  /go1.11.tgz
export PATH=$PATH:/usr/local/go/bin

curl https://raw.githubusercontent.com/golang/dep/master/install.sh | GOBIN=/usr/local/go/bin sh

cd /go-speedracer-go
git submodule update --init --recursive
autoreconf -fiv
./configure --enable-analysis-engine --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make dep
make install

#configure env
#ln -s /usr/local/nginx/sbin/nginx /bin/nginx
#cp /usr/src/modsecurity/unicode.mapping /usr/local/nginx/conf/
mkdir -p /opt/modsecurity/var/audit/

#install signature
#git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git /usr/src/owasp-modsecurity-crs
#cd /usr/src/owasp-modsecurity-crs
#git checkout v3.0.2
#cd /
#cp -R /usr/src/owasp-modsecurity-crs/rules /usr/local/nginx/conf/
#mv /usr/local/nginx/conf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf{.example,}
#mv /usr/local/nginx/conf/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf{.example,}

#apt-get purge -y build-essential wget git
#rm /nginx-1.14.0.tar.gz



