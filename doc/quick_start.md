# Quick Start

## Kubernetes

### Prerequisite

#### Create NIC SR-IOV network resource pool

> In order to maximize the throughput of LBU, 
> it is necessary to bind the external network port of LBU to a separate physical network port,
> and other internal shunted network ports can use the virtual network port of SR-IOV

> At least three SR-IOV virtual network ports (SMU FPU LBU) and one separate physical network port (LBU) are required

[detail](references.md#sr-iov-network-device-plugin-for-kubernetes)

#### Configure the CPU manager policy of kubernetes to static

See [CPU-manager-policy configuration](references.md#kubernetes-configure-cpu-manager-policy)

### Deploy

```shell
$ git clone https://github.com/5GOpenUPF/openupf-deploy-script.git
$ cd openupf-deploy-script/deploy_upf
$ ./deploy_upf.sh all
```

If you need to clear the deployed openupf, just execute the following command

```shell
$ cd openupf-deploy-script/deploy_upf
$ ./clean_upf.sh all
```

## Docker

```shell
$ git clone https://github.com/5GOpenUPF/openupf.git
```

### Prerequisite

#### Create NIC SR-IOV

```shell
# modprobe -r ixgbe
# modprobe ixgbe max_vfs=4
# modprobe vfio-pci
# /usr/bin/chmod a+x /dev/vfio
# /usr/bin/chmod 0666 /dev/vfio/*

# cd openupf/install/script
# ./dpdk-devbind.py –b ixgbevf 04:10.7
# ./dpdk-devbind.py –b vfio-pci 04:10.0
# ./dpdk-devbind.py –b vfio-pci 04:10.1
# ./dpdk-devbind.py –b vfio-pci 04:10.2
# ./dpdk-devbind.py –b vfio-pci 04:10.3
# ./dpdk-devbind.py –b vfio-pci 04:10.4
# ./dpdk-devbind.py –b vfio-pci 04:10.5
# ./dpdk-devbind.py –b vfio-pci 04:10.6
```

### Modify configuration

```shell
$ cd openupf
$ vi config/smu/smu_docker.ini
$ vi config/smu/lbu_docker.ini
$ vi config/smu/fpu_dpdk_docker.ini
$ cd install/script
$ vi docker_dpdk_run_upf.sh
```

### Build

```shell
$ cd openupf/build
$ ./build.sh
```

### Deploy

```shell
$ cd openupf / install/script
$ ./start_upf.sh
```