# 系统配置
基于centos7.4以上版本

service smb start
iptables -F
service docker start

# 初始化系统巨页
方法1:配置sysctl
```
echo 'vm.nr_hugepages=2048' >> /etc/sysctl.conf
sysctl -p
```
方法2:修改系统grub参数
```
vim /etc/default/grub
GRUB_CMDLINE_LINUX中增加：default_hugepagesz=2M hugepagesz=2M hugepages=2048 iommu=pt intel_iommu=on
grub2-mkconfig -o /boot/grub2/grub.cfg

reboot
```


# 绑定指定网口到dpdk模式（vfio）
```
sudo modprobe vfio-pci
sudo /usr/bin/chmod a+x /dev/vfio
sudo /usr/bin/chmod 0666 /dev/vfio/*

export NIC_PCIE_ADDR="0000:43:00.1"
sudo ifconfig $(ls /sys/bus/pci/devices/$NIC_PCIE_ADDR/net) down
sudo ./dpdk-devbind.py --bind=vfio-pci $(ls /sys/bus/pci/devices/$NIC_PCIE_ADDR/net) 
sudo ./dpdk-devbind.py --status
```

# 绑定指定网口到dpdk模式（uio）（如果vfio不行就试试uio，23的板子使用uio是可以的）
```
export NIC_PCIE_ADDR="0000:43:00.1"
sudo ifconfig $(ls /sys/bus/pci/devices/$NIC_PCIE_ADDR/net) down
sudo modprobe uio
sudo insmod ../../build/dpdk/kmod/igb_uio.ko
sudo ./dpdk-devbind.py --bind=igb_uio $(ls /sys/bus/pci/devices/$NIC_PCIE_ADDR/net)
或：sudo ./dpdk-devbind.py --bind=igb_uio  "00:14.0"
sudo ./dpdk-devbind.py --status
```


# 系统巨页默认已经挂载了，如果没有手动挂载一下
```
sudo mount -t hugetlbfs none /dev/huge
```


如果dpdk成功配置：
[root@localhost script]# sudo ./dpdk-devbind.py --status

Network devices using DPDK-compatible driver
============================================
0000:00:14.3 'Ethernet Connection I354 1f41' drv=igb_uio unused=igb,vfio-pci

Network devices using kernel driver
===================================
0000:00:14.0 'Ethernet Connection I354 1f41' if=eno1 drv=igb unused=igb_uio,vfio-pci 
0000:00:14.1 'Ethernet Connection I354 1f41' if=eno2 drv=igb unused=igb_uio,vfio-pci 
0000:00:14.2 'Ethernet Connection I354 1f41' if=eno3 drv=igb unused=igb_uio,vfio-pci *Active*

Other Crypto devices
====================
0000:00:0b.0 'Atom processor C2000 QAT 1f18' unused=igb_uio,vfio-pci

No 'Eventdev' devices detected
==============================

No 'Mempool' devices detected
=============================

No 'Compress' devices detected
==============================
[root@localhost script]# 

