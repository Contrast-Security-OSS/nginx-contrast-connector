#!/bin/sh

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

#make modsecurity-nginx
cd /nginx-speedracer-connector
make install

#cp -R docker-builds/go-speedracer-go /go-speedracer-go

curl -o /go1.11.tgz https://dl.google.com/go/go1.11.linux-amd64.tar.gz
tar -C /usr/local -xzvf  /go1.11.tgz
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



