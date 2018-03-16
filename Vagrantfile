# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://atlas.hashicorp.com/search.
  config.vm.box = "ubuntu/xenial64"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  config.vm.network "forwarded_port", guest: 80, host: 18000
  config.vm.network "forwarded_port", guest: 8080, host: 18080

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  config.vm.network "private_network", ip: "192.168.33.12"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  config.vm.synced_folder "../go-speedracer-go", "/go/src/contrast/speedracer"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  # config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
  #   vb.memory = "1024"
  # end
  #
  # View the documentation for the provider you are using for more
  # information on available options.

  # Define a Vagrant Push strategy for pushing to Atlas. Other push strategies
  # such as FTP and Heroku are also available. See the documentation at
  # https://docs.vagrantup.com/v2/push/atlas.html for more information.
  # config.push.define "atlas" do |push|
  #   push.app = "YOUR_ATLAS_USERNAME/YOUR_APPLICATION_NAME"
  # end

  # Enable provisioning with a shell script. Additional provisioners such as
  # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
  # documentation for more information about their specific syntax and use.
  config.vm.provision "shell", inline: <<-SHELL
    
    # install base development libraries
    apt-get update
    apt-get -y upgrade
    apt-get -y install gcc g++ make lua5.3 liblua5.3-0 liblua5.3.dev libxml2-dev software-properties-common unzip
    apt-get -y install libc6-dev flex bison curl doxygen libyajl-dev libgeoip-dev libtool dh-autoreconf libcurl4-gnutls-dev libxml2 libpcre++-dev libxml2-dev

    # build and install libmodsecurity
    git clone https://github.com/SpiderLabs/ModSecurity
    cd ModSecurity/
    git checkout -b v3/master origin/v3/master
    sh build.sh
    git submodule init
    git submodule update
    ./configure
    sudo chown -R ubuntu /usr/local
    make
    make install

    # adding the libmodsecurity headers to the library path
    echo "LD_LIBRARY_PATH=/usr/local/modsecurity/lib" >> ~/.profile_example

    # downloading the owasp rules
    git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git

    # install GO as ubuntu user
    sudo su - ubuntu
    cd ~
    wget -q https://dl.google.com/go/go1.10.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.10.linux-amd64.tar.gz

    chown -R ubuntu /go
    echo 'export GOHOME=/go' > .go-profile
    echo 'export GOROOT=/usr/local/go' >> .go-profile
    echo 'export GOBIN=/usr/local/go/bin' >> .go-profile
    exit
  

  SHELL
end
