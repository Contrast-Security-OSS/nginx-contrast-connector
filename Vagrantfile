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
  # boxes at https://vagrantcloud.com/search.
  config.vm.box = "centos/7"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # NOTE: This will enable public access to the opened port
  config.vm.network "forwarded_port", guest: 80, host: 18000
  config.vm.network "forwarded_port", guest: 8888, host: 18888

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  config.vm.network "private_network", ip: "192.168.33.0"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  config.vm.synced_folder "../../projects/go-speedracer-go", "/go/src/contrast/speedracer", owner: "vagrant", group: "vagrant"

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

  # Enable provisioning with a shell script. Additional provisioners such as
  # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
  # documentation for more information about their specific syntax and use.
  config.vm.provision "shell", inline: <<-SHELL
    
    yum update
    yum upgrade

    # base stuff
    yum -y install vim git bash wget 

    # install base development libraries
    yum -y install gcc gcc-c++ make lua-devel libxml2-devel software-properties-common unzip
    yum -y install flex bison curl doxygen libyajl-devel libtool libtool-ltdl-devel dh-autoreconf 
    yum -y install pcre-devel pcre pcre-cpp GeoIP-devel libcurl-devel zlib-devel yajl yajl-devel lmdb lmdb-devel ssdeep ssdeep-devel

    # build and install libmodsecurity
    git clone https://github.com/SpiderLabs/ModSecurity
    cd ModSecurity/
    git checkout -b v3/master origin/v3/master
    sh build.sh
    git submodule init
    git submodule update
    ./configure
    sudo chown -R vagrant /usr/local
    make
    make install

    # adding the libmodsecurity headers to the library path
    echo "LD_LIBRARY_PATH=/usr/local/modsecurity/lib" >> ~/.profile_example

    # downloading the owasp rules
    git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git

    # install GO as vagrant user
    sudo su - vagrant
    cd ~
    wget -q https://dl.google.com/go/go1.10.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.10.linux-amd64.tar.gz

    chown -R vagrant /go
    echo 'export GOHOME=/go' > .go-profile
    echo 'export GOROOT=/usr/local/go' >> .go-profile
    echo 'export GOBIN=/usr/local/go/bin' >> .go-profile
    exit
  
  SHELL
end
