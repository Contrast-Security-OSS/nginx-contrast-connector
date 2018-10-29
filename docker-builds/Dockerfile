FROM ubuntu
MAINTAINER contrastsecurity.net
RUN apt-get update -y && apt-get install -y curl gnupg2

RUN curl https://contrastsecurity.jfrog.io/contrastsecurity/api/gpg/key/public | apt-key add -
RUN echo "deb https://contrastsecurity.jfrog.io/contrastsecurity/debian-staging/ bionic contrast" > /etc/apt/sources.list.d/contrast.list
RUN apt-get update && apt-get install -y contrast-modsecurity flex bison libgeoip-dev git wget build-essential libpcre3 libpcre3-dev libssl-dev libtool autoconf apache2-dev libxml2-dev libcurl4-openssl-dev psmisc vim


ADD docker-builds/build.sh /build.sh
ADD . /nginx-speedracer-connector
ADD docker-builds/go-speedracer-go /go-speedracer-go
RUN chmod +x /build.sh && /bin/bash -c "source /build.sh"

ADD docker-builds/nginx.conf /usr/local/nginx/conf/nginx.conf
ADD contrast_security.yaml /etc/contrast/webserver/contrast_security.yaml

#ADD modsec_includes.conf /usr/local/nginx/conf/modsec_includes.conf
#ADD modsecurity.conf /usr/local/nginx/conf/modsecurity.conf
#ADD crs-setup.conf /usr/local/nginx/conf/rules/crs-setup.conf
#COPY custom-rules/* /usr/local/nginx/conf/rules/
CMD (/usr/bin/Contrast-Service &) && /usr/local/nginx/sbin/nginx -g 'daemon off;'

EXPOSE 80
