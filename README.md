# NGINX / Speedracer Connector #

This is a statically compiled module that allows NGINX to communicate with Speedracer using UNIX sockets and protobuf messages.

### What is this repository for? ###

This repository is a build environment heavily influenced by the tutorial code from Aaron Bedra
[here](https://github.com/abedra/nginx-auth-token-module) and the libmodsecurity connector from SpiderLabs
[here](https://github.com/SpiderLabs/ModSecurity-nginx).

This repository attempts to build all the compiled libraries necessary including:

* libmodsecurity (c++)
* OWASP libmodesecurty rule set (text)
* NGINX (c++)
* NGINX connector (c) 
* Speedracer (go)

### How do I get set up? ###

The current connector is designed to be setup and tested in a 
[Vagrant](https://www.vagrantup.com/)/[VirtualBox](https://www.virtualbox.org/) virtual machine.

* `vagrant up`
* `vagrant ssh`
* install RVM rb-env to get access to a modern ruby
* `cd /vagrant`
* `chmod +x script/*`
* `script/bootstrap`
* `gem install bundler`
* `bundle install`
* `rake nginx:compile`
* `rake`

Assuming all the steps succeed, you now have a NGINX instance with the speedracer connector module staticly linked.  Next steps are to setup speedracer configured for Unix sockets and ensure that speedracer can communicate with Teamserver on the host machine.

Next, you probably want to run Speedracer considering this project is called the NGINX / Speedracer Connector.  The vagrant provision should have downloaded and installed the libmodsecurity library as well as the OWASP rule sets. The library headers need to be added to the library path. Add the following to ~/.profile

    LD_LIBRARY_PATH="/usr/local/modsecurity/lib"
	
It should have also installed Go however the provisioner didn't update the profile correctly (unless this has been fixed) so edit your ~/.profile to add the following to the PATH. 

    # Add GO to PATH
    export GOHOME="/go"
    export GOROOT="/usr/local/go"
    export GOBIN="$GOROOT/bin"
    export PATH="$PATH:$GOBIN"

The speedracer project should be mounted in the vagrant environment at `/go/src/contrast/speedracer` assuming this project and the speedracer project are both in sibling directories.

* cd `/go/src/contrast/speedracer`
* `curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh`
* `dep ensure`
    * NOTE: `dep` has a bug that prevents it working under virtual machines (?) which may require installing dependencies individually.

	
Next `dep` seems to have a bug where it won't correctly lock 

### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact
