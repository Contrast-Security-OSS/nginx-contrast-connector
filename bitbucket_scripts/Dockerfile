FROM ubuntu:xenial

WORKDIR /app/

RUN mkdir -p /app/bin && mkdir -p /app/src/contrast/

ENV GOROOT="/usr/local/go"
ENV GOPATH="/app/"
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

COPY contrast-modsecurity contrast-modsecurity
COPY nginx-speedracer-connector nginx-speedracer-connector
COPY owasp-modsecurity-crs owasp-modsecurity-crs
 
# Install ModSecurity Deps, NGINX, Docker
RUN apt-get update && apt-get install -y \ 
sudo \
curl \
wget \
devscripts \
dh-autoreconf \
dh-systemd \
debhelper \
libgeoip-dev \
libfuzzy-dev \
libyajl-dev \
libcurl4-openssl-dev \
liblmdb-dev \
liblua5.2-dev \
libperl-dev \
perl-modules \
cpio \
gawk \
libxml2-dev \
libpcre3-dev \
libreadline6 \
apt-utils \
software-properties-common \
autoconf \
libtool \
# Docker Deps
ca-certificates \
apt-transport-https \
# Ruby Deps
gnupg2 \
# Utils
git \
wget \
nginx \
git \
curl \
vim 

# Add NGINX & Docker to sources
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable" && curl -O https://nginx.org/keys/nginx_signing.key && sudo apt-key add nginx_signing.key && echo 'deb http://nginx.org/packages/ubuntu/ xenial nginx' >> /etc/apt/sources.list && \
   echo 'deb-src http://nginx.org/packages/ubuntu/ xenial nginx' >> /etc/apt/sources.list  

RUN apt-get update && apt-get install -y nginx

# Install Go
RUN wget https://dl.google.com/go/go1.10.1.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.10.1.linux-amd64.tar.gz

# Install RVM & Ruby 2.3.4
RUN curl -sSL https://rvm.io/mpapis.asc | gpg --import - && \
curl -sSL https://get.rvm.io | bash
RUN /bin/bash -l -c ". /etc/profile.d/rvm.sh && rvm install 2.3.4"

# Install Golang Dep
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh


# Build ModSecurity Package + Setup SpeedRacer Deps
RUN cd contrast-modsecurity && ./deb/build-pkg.sh && cd deb && apt install ./modsecurity_3.0.2-1_amd64.deb && \
cd /app/contrast-modsecurity/deb/modsecurity-3.0.2/src && mkdir -p /usr/local/modsecurity/lib/ && \
cp .libs/* /usr/local/modsecurity/lib/

# Install NGINX Connector
RUN cd nginx-speedracer-connector && git submodule update --init --recursive \
&& ./build_module.sh -y -f -n contrast -v 1.14.1 /app/nginx-speedracer-connector && \
cd ~/debuild && dpkg -i nginx-module-contrast_1.14.1-1~xenial_amd64.deb && \
cd /etc/nginx && mkdir -p /etc/nginx/logs/ && \
mv /app/nginx-speedracer-connector/nginx.conf nginx.conf && \
echo 'user root;' >> nginx.conf && service nginx stop

# Configure OWASP Rules
RUN cd /app/nginx-speedracer-connector && cp /app/nginx-speedracer-connector/vendor/crs-setup.conf /app/owasp-modsecurity-crs/. && \
cp /app/nginx-speedracer-connector/vendor/modsecurity.conf /app/owasp-modsecurity-crs/. && \
sudo touch /var/log/modsec_audit.log && \
sudo chown root /var/log/modsec_audit.log
