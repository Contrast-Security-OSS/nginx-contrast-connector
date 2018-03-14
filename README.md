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

Assuming all the steps succeed, you now have a NGINX instance with the speedracer connector module staticly linked.  
Next steps are to setup speedracer configured for Unix sockets and ensure that speedracer can communicate with Teamserver on the host machine.


### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact
