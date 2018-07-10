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
  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 4
  end

  # These definitions will build a VM suitable for creating a deb package.
  ['trusty', 'xenial', 'artful', 'bionic'].each do |release|
    config.vm.define "ubuntu-#{release}" do |ubuntu|
      ubuntu.vm.box = "ubuntu/#{release}64"

      # Create a forwarded port mapping which allows access to a specific port
      # within the machine from a port on the host machine.
      #ubuntu.vm.network "forwarded_port", guest: 80, host: 18000
      #ubuntu.vm.network "forwarded_port", guest: 8888, host: 18888
      #ubuntu.vm.network "forwarded_port", guest: 4567, host: 14567

      # Create a private network, which allows host-only access to the machine
      # using a specific IP.
      ubuntu.vm.network "private_network", type: "dhcp"

      # Share an additional folder to the guest VM. The first argument is
      # the path on the host to the actual folder. The second argument is
      # the path on the guest to mount the folder. And the optional third
      # argument is a set of non-required options.
      ubuntu.vm.synced_folder "../../projects", "/projects"

      # Enable provisioning with a shell script. Additional provisioners such as
      # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
      # documentation for more information about their specific syntax and use.
      ubuntu.vm.provision "shell", inline: <<-SHELL
    
        # install base development libraries
        apt-get update
        apt-get -y upgrade
        apt-get -y install devscripts build-essential gcc g++ make unzip autoconf libtool
    
        exit

        SHELL
    end  # ubuntu/${release} block
  end # each release
  
  config.vm.define "ubuntu-test" do |test|
    test.vm.box = "ubuntu/xenial64"
    test.vm.network "forwarded_port", guest: 80, host: 18000
    test.vm.network "forwarded_port", guest: 8888, host: 18888
    test.vm.network "forwarded_port", guest: 4567, host: 14567
    test.vm.network "private_network", type: "dhcp"
    test.vm.synced_folder "../../projects/go-speedracer-go", "/go/src/contrast/speedracer"
    test.vm.provision "shell", inline: <<-SHELL
    
        # install base development libraries
        apt-get update
        apt-get -y upgrade
        apt-get -y install gcc g++ make unzip autoconf libtool
    
        exit

    SHELL

  end # test
end
