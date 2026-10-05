/container/add name=awg3 hostname=amnezia interface=docker-awg-veth mountlists=awg_conf envlist=awg_env root-dir=usb1-part1/awg-root layer-dir=usb1-part1/awg-layers logging=yes start-on-boot=no dns=172.18.20.1 memory-high=33554432 memory-max=41943040 file=usb1-part1/awg3-arm-current.tar
:put "AWG3 image installation requested"
