# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://atlas.hashicorp.com/search.
  config.vm.box = "centos/7"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  config.vm.network "forwarded_port", guest: 8000, host: 8000, host_ip: "0.0.0.0"
  config.vm.network "forwarded_port", guest: 443, host: 8443, host_ip: "0.0.0.0"

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

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
   config.vm.provision "shell", path: "install-centos.sh"

   config.vm.provision "shell", inline: <<-SHELL
     systemctl enable redis
     systemctl start redis
     
#     systemctl enable mariadb.service
#     service mariadb start
#     mysql -u root <<-SCRIPT
#create database fod;
#SCRIPT

     echo "Installation of Shibboleth" >&2

     echo "TODO fix SELinux"
     setenforce permissive

     (cd /srv/flowspy/inst/apache_shib/; ./apache_shib_init.sh;)

     echo "To set environment to English, run: export LC_ALL=en_US"
     echo "To activate virualenv: source /srv/venv/bin/activate"
     echo "To create a user run: cd /srv/flowspy; ./manage.py createsuperuser"
     echo "To start flowspy server: cd /srv/flowspy; ./manage.py runserver 0.0.0.0:8000"
     echo "To start celeryd: cd /srv/flowspy; ./manage.py celeryd"
   SHELL
end
