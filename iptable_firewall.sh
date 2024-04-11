#!/bin/bash
set -euo pipefail

src_ip=$(kubectl get pods busyboxc1 -o json | jq -r '.status.podIP')
dst_ip=$(kubectl get pods busyboxc2 -o json | jq -r '.status.podIP')


if [ "$1" == "uninstall" ]; then
    echo "uninstall the firewall rule to unblock c1 to c2"
    docker exec l3cni-two-node-control-plane iptables -D FORWARD -s $src_ip -d $dst_ip -j DROP
elif [ "$1" == "install" ]; then
    echo "install the firewall rule to block c1 to c2"
    docker exec l3cni-two-node-control-plane iptables -A FORWARD -s $src_ip -d $dst_ip -j DROP
else
    echo "Usage: $0 [uninstall|install]"
fi
