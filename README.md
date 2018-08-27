# NGINX / Speedracer Connector

This is an NGINX module that can be compiled statially or dynamically that
allows NGINX to communicate with Speedracer using tcp or UNIX sockets with
protobuf messages.

# What is this repository for?

This repository is a build environment heavily influenced by the tutorial code
from Aaron Bedra [here](https://github.com/abedra/nginx-auth-token-module) and
the libmodsecurity connector from SpiderLabs
[here](https://github.com/SpiderLabs/ModSecurity-nginx).

This repository attempts to build all the compiled libraries necessary
including:

* NGINX connector (c) 
* protobuf-c

# Building

Before doing anything, run:

    git submodule update --init --recursive

This is going to sync up your git submodules. It likely hardly ever going to be
updated so you'll probably only going to need to run this like once a year, if
that.

To compile, Just run

    make

and it will build a module for the current targeted stable nginx release. To
build for other versions of nginx, pass the `V` env var to `make` with the
version of nginx you want to build against:

    make V=1.14.0

Module binaries will be left in `vendor/nginx-<version>/objs/`

# Install

This depends on how you want the module on your system. Running:

    make install # or make V=<nginx version> install

will install the nginx server and this connector module using the nginx install
receipe. This will likely put everything under /usr/local/nginx. This will work
fine but you are on your own for running the nginx server and configuring it.
Once this is done once, it will probably be an efficient cycle of development
to call `make install` and repopulate the module on the system.

Alternatively, you can install an nginx system package (from the nginx.org pkg
repositories) and then nginx will be integrated with your system start/stop
services. To get your module in play you can run:

    cp vendor/nginx-<version>/objs/*.so /etc/nginx/modules/

Assuming you've already configured the module and app for contrast protection,
this will have nginx find you module and use it.

See the section below about configuring nginx to use the module and how to
configure an app to be protected by the contrast webserver agent.

# Configuring the webserver agent connector

Regardless of how you install nginx and the contrast connector module, you will
need to tell nginx to load and use the module. Here are steps for editing nginx
configs when installed from a package.  If you install via `make install`
above, the location of the config files will be different, but the actions and
modification will remain the same.

First tell nginx to load the module. Append this to the top of `/etc/nginx/nginx.conf`
    
    load_module modules/ngx_http_contrast_connector_module.so;

Next add the following lines to `nginx.conf` to globally enable the contrast
connector module. This should be done within an 'http { }' directive in nginx.
    
    contrast on;
    contrast_debug on;
    contrast_unix_socket "/run/contrast-service.sock";

Finally, under each 'location { }' directive in nginx.conf, add the following:

    contrast_app_name "<your app name>"

Replace `<your app name>` obviously with some identifying name for your app. It
doesn't matter what you choose, but this will be the name of the app when it is
automatically registered in TeamServer.

# Other stuff I don't know where to put...

The connector module can be tested in a vagrant vm or docker image, your
choice. If using docker, the following `Dockerfile` will help jumpstart your
testing.

    FROM contrast/installer-build:ubuntu-18
    RUN curl https://contrastsecurity.jfrog.io/contrastsecurity/api/gpg/key/public | apt-key add -
    RUN echo "deb https://contrastsecurity.jfrog.io/contrastsecurity/debian-staging/ bionic contrast" > /etc/apt/sources.list.d/contrast.list
    RUN curl -O https://nginx.org/keys/nginx_signing.key && apt-key add nginx_signing.key && echo 'deb http://nginx.org/packages/ubuntu/ bionic nginx' >> /etc/apt/sources.list && echo 'deb-src http://nginx.org/packages/ubuntu/ bionic nginx' >> /etc/apt/sources.list
    RUN apt-get update -y
    RUN sudo apt-get install ruby-curb ruby-dev -y
    RUN apt-get install contrast-webserver-agent-nginx contrast-service -y

to create it, 

    docker build -t waf-testing .

to run it,

    docker run -it waf-testing /bin/bash

Some of this info will is duplicated by the speedracer project, but at this
point you need to configure you contrast-service to speak with your TS
instance. You will also need to configure nginx to load and use the contrast
connectory module. Looking at testing/integrations.sh in the speedracer
project may help jumpstart that.

For most testing and operation, see the speedracer project as that is the
central place where system test scripts are located.

# Building an native linux packages
* `vagrant up <ubuntu flavor>`
* `vagrant ssh <ubuntu flavor>`
* `cd /vagrant`
* `./build_module.sh -n contrast -v <nginx version> .`

The module will be left in /home/vagrant/debuild/nginx-<version>/debian/debuild-module-contrast/

For rpms, same steps apply. The build_module.sh tool will detect the platform
and build packages suitable for it, ie rpm or deb.  Rpms are left in
/home/vagrant/rpmbuild/RPMS

# How do I test?

See the speedracer documentation for how to configure speedracer to speak with
TeamServer and its Agents. Once speedracer is configured properly this
connector can be configured.  Take care to follow the documentation in
speedracer to enabling the Proxy/WAF feature in TS and enabling the Proxy/WAF
rules in TS otherwise speedracer won't enforce blocking http requests when it
should for testing.

Next, NGINX won't forward POST and PUT request to static resources so you need
to have a "real" server to proxy to. I've setup a simple sinatra app to receive
requests. Run `rake sinatra:start` to fire that up. The sinatra testing app is
maintained in the speedracer repo.

# Contribution guidelines

* Writing tests
* Code review
* Other guidelines
* Coding Style
    http://nginx.org/en/docs/dev/development_guide.html#code_style

# Who do I talk to?

* Repo owner or admin
* Other community or team contact
