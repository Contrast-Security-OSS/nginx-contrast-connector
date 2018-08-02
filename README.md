# NGINX / Speedracer Connector #

This is an NGINX module that can be compiled statially or dynamically that
allows NGINX to communicate with Speedracer using tcp or UNIX sockets with
protobuf messages.

### What is this repository for? ###

This repository is a build environment heavily influenced by the tutorial code
from Aaron Bedra [here](https://github.com/abedra/nginx-auth-token-module) and
the libmodsecurity connector from SpiderLabs
[here](https://github.com/SpiderLabs/ModSecurity-nginx).

This repository attempts to build all the compiled libraries necessary
including:

* NGINX (c++)
* NGINX connector (c) 

### How do I get set up? ###

The current connector is designed to be setup and tested in a 
[Vagrant](https://www.vagrantup.com/)/[VirtualBox](https://www.virtualbox.org/) virtual machine.

* `vagrant status` # to see the list of available VMs
* `vagrant up ubuntu-xenial`
* `vagrant ssh`
* install RVM rb-env to get access to a modern ruby (https://rvm.io/)
* `cd /vagrant`
* `chmod +x script/*`
* `script/bootstrap`
* `gem install bundler`
* `bundle install`
* `rake nginx:compile`
* start up a Sinatra app so POST requests can be tested: `rake sinatra:start` 
* `rake`

Assuming all the steps succeed, you now have a NGINX instance with the speedracer connector module staticly linked.  Next steps are to setup speedracer configured for Unix sockets and ensure that speedracer can communicate with Teamserver on the host machine.

Next, you probably want to run Speedracer considering this project is called the NGINX / Speedracer Connector.  The vagrant provision should have downloaded and installed the libmodsecurity library as well as the OWASP rule sets. The library headers need to be added to the library path. Add the following to ~/.profile

    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+LD_LIBRARY_PATH:}/usr/local/lib:/usr/local/modsecurity/lib"
	
It should have also installed Go however the provisioner didn't update the profile correctly (unless this has been fixed) so edit your ~/.profile to add the following to the PATH. 

    # Add GO to PATH
    export GOHOME="/go"
    export GOROOT="/usr/local/go"
    export GOBIN="$GOROOT/bin"
    export PATH="$PATH:$GOBIN"

The speedracer project should be mounted in the vagrant environment at `/go/src/contrast/speedracer` assuming this project and the speedracer project are both in sibling directories. You'll need to be in the `protect-with-modsec` branch of speedracer for speedracer to link to the ModSecurity library.

* cd `/go/src/contrast/speedracer`
* `curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh`
* `dep ensure`
    * NOTE: `dep` has a bug that prevents it working under virtual machines (?) which may require installing dependencies individually.

### Building an ubuntu package
* `vagrant up <ubuntu flavor>`
* `vagrant ssh <ubuntu flavor>`
* `cd /vagrant`
* `./build_module.sh -n contrast -v <nginx version> /vagrant`

The module will be left in /home/vagrant/debuild/nginx-<version>/debian/debuild-module-contrast/
	
### How do I test? ###

After you're set up you should have a Speedracer instance running on the vagrant box. The `contrast_security.yaml` should be setup to communicate out to Teamserver instance (for my vagrant, `url: http://10.0.2.2:19980/Contrast` seemed to work). To get Teamserver to recognize ModSecurity as a rule, use the `local-modsecurity-rule` branch in Teamserver.

You'll need to enable the `ModSecurity` rule in teamserver. 

    insert ignore into rasp_protection_rules (uuid, name, category, description, can_block_at_perimeter) 
        values ('mod-security', 'ModSecurity', 'Input Validation', 'A vulnerability identified by the libmodsecurity library and the open source OWASP rule set.', 1);
    
    insert ignore into rasp_protection_rules_languages (protection_rules_id, language) 
        values (the_id_from_the_previous_insert, 'RUBY');

Next, NGINX won't forward POST and PUT request to static resources so you need to have a "real" server to proxy to. I've setup a simple sinatra app to receive requests. Run `rake sinatra:start` to fire that up.

When you run `rake` in the project root (i.e. `/vagrant`) it will attempt startup NGINX server with a location `/sinatra` that will proxy to the sinatra server. The request body filter in the connector will intercept that request and build a protobuf `RawRequest` instance and make a unix socket connection to speedracer (make sure speedracer is using unix sockets at `socket: /tmp/contrast-service.sock` not the tcp endpoint). Speedracer should parse it and send back an exception if an attack is seen. 

### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines
* Coding Style
    http://nginx.org/en/docs/dev/development_guide.html#code_style

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact
