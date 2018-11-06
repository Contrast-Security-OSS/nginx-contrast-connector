#!/bin/bash

set -e

apt-get update -y && apt-get install -y curl gnupg2
curl https://contrastsecurity.jfrog.io/contrastsecurity/api/gpg/key/public | apt-key add -
echo "deb https://contrastsecurity.jfrog.io/contrastsecurity/debian-staging/ bionic contrast" > /etc/apt/sources.list.d/contrast.list
apt-get update && apt-get install -y contrast-modsecurity contrast-service flex bison libgeoip-dev git wget build-essential libpcre3 libpcre3-dev libssl-dev libtool autoconf apache2-dev libxml2-dev libcurl4-openssl-dev psmisc vim

cd ../ && ls && pwd
mv docker-builds/nginx.conf /usr/local/nginx/conf/nginx.conf
mv docker-builds/contrast_security.yml /etc/contrast/webserver/contrast_security.yaml

package=$(ls ./pkgs | grep "bionic" | head -n 1)
apt install ./pkgs/${package} -y
git clone https://github.com/nginx/nginx-tests.git
(/usr/bin/Contrast-Service &) && cd nginx-tests && TEST_NGINX_GLOBALS="load_module modules/ngx_http_contrast_connector_module.so;" TEST_NGINX_GLOBALS_HTTP="contrast on;" TEST_NGINX_BINARY=/usr/local/nginx/sbin/nginx prove .