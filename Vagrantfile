# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  # Determine available host resources
  mem_ratio = 1.0/2
  cpu_exec_cap = 75
  host = RbConfig::CONFIG['host_os']
  # Give VM 1/2 system memory & access to all cpu cores on the host
  if host =~ /darwin/
    cpus = `sysctl -n hw.ncpu`.to_i
    # sysctl returns Bytes and we need to convert to MB
    mem = `sysctl -n hw.memsize`.to_i / (1024^2) * mem_ratio
  elsif host =~ /linux/
    cpus = `nproc`.to_i
    # meminfo shows KB and we need to convert to MB
    mem = `grep 'MemTotal' /proc/meminfo | sed -e 's/MemTotal://' -e 's/ kB//'`.to_i / 1024 * mem_ratio
  else # Windows folks
    cpus = `wmic cpu get NumberOfCores`.split("\n")[2].to_i
    mem = `wmic OS get TotalVisibleMemorySize`.split("\n")[2].to_i / 1024 * mem_ratio
  end
  config.vm.boot_timeout = 1800
  # Provision the "MiniNetVirtualMachine"
  config.vm.define :mnvm do |mnvm|
    mnvm.vm.box = "ubuntu/focal64"
    mnvm.vm.hostname = "mnvm"
    mnvm.vm.synced_folder ".", "/vagrant", disabled: false
    mnvm.ssh.forward_agent = true
    mnvm.ssh.forward_x11 = true

    if mem < 2048
      puts "Your machine might not have enough memory to run this VM! Talk to the course staff."
    end

    mnvm.vm.provider "virtualbox" do |vb|
      vb.customize ["modifyvm", :id, "--cpuexecutioncap", 75]
      vb.customize ["modifyvm", :id, "--memory", "2048"]
      vb.customize ["modifyvm", :id, "--cpus", "2"]
    end

    mnvm.vm.provision "shell", path: "bootstrap.sh", privileged: true

  end

end

