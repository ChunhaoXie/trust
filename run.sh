#!/bin/bash
sudo setcap cap_net_admin=eip ~/CLionProjects/trust/target/debug/trust
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
# ping -I tun0 192.168.0.2
telnet 192.168.0.2 9999
