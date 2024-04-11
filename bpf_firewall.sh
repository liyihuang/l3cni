#!/bin/bash
set -euo pipefail
echo "get the c1 and c2 ip address"
src_ip=$(kubectl get pods busyboxc1 -o json | jq -r '.status.podIP' | sed 's/\./ /g')
dst_ip=$(kubectl get pods busyboxc2 -o json | jq -r '.status.podIP' | sed 's/\./ /g')
host_interface=$(echo "$src_ip" | awk '{print $NF}')


if [ "$1" == "uninstall" ]; then
    echo "uninstall bpf program from the interface"
    docker exec l3cni-two-node-control-plane tc qdisc delete dev host-$host_interface clsact
elif [ "$1" == "install" ]; then
    echo "compile the bpf firewall and install bpftool on k8s node"
    clang -g -O2 -target bpf -Wall -c bpf_firewall.c -o bpf_firewall.o

    docker exec l3cni-two-node-control-plane apt update
    docker exec l3cni-two-node-control-plane apt install bpftool -y
    echo "copy bpf program to k8s node"
    docker cp bpf_firewall.o l3cni-two-node-control-plane:/root

    echo "load the bpf program to the interface and update the bpf map"
    docker exec l3cni-two-node-control-plane tc qdisc add dev host-$host_interface clsact
    docker exec l3cni-two-node-control-plane tc filter add dev host-$host_interface ingress bpf da obj /root/bpf_firewall.o sec ingress
    docker exec l3cni-two-node-control-plane bpftool map update name bpf_match key $src_ip value $dst_ip

else
    echo "Usage: $0 [uninstall|install]"
fi




