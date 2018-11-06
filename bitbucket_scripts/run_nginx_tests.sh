#!/bin/bash

set -e

apt-get update -y && apt-get install -y curl gnupg2
curl https://contrastsecurity.jfrog.io/contrastsecurity/api/gpg/key/public | apt-key add -
echo "deb https://contrastsecurity.jfrog.io/contrastsecurity/debian-staging/ bionic contrast" > /etc/apt/sources.list.d/contrast.list
apt-get update && apt-get install -y contrast-modsecurity contrast-service flex bison libgeoip-dev git wget build-essential libpcre3 libpcre3-dev libssl-dev libtool autoconf apache2-dev libxml2-dev libcurl4-openssl-dev psmisc vim

curl -L -o /nginx-1.14.0.tar.gz http://nginx.org/download/nginx-1.14.0.tar.gz && tar -xzf /nginx-1.14.0.tar.gz
cd nginx-1.14.0 && ./configure --with-compat \
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
          --without-http_uwsgi_module && make -j4 install

cd ../
mv docker-builds/nginx.conf /usr/local/nginx/conf/nginx.conf && sed -i 's%modules%/usr/lib/nginx/modules%g' /usr/local/nginx/conf/nginx.conf
mv docker-builds/contrast_security.yml /etc/contrast/webserver/contrast_security.yaml

package=$(ls ./pkgs | grep "bionic")
apt install ./pkgs/${package} -y
git clone https://github.com/nginx/nginx-tests.git
(/usr/bin/Contrast-Service &) && cd nginx-tests && TEST_NGINX_GLOBALS="load_module /usr/lib/nginx/modules/ngx_http_contrast_connector_module.so;" TEST_NGINX_GLOBALS_HTTP="contrast on;" TEST_NGINX_BINARY=/usr/local/nginx/sbin/nginx prove .