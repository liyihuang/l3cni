#!/bin/bash

controller_node_mac_bpf=$(docker inspect l3cni-two-node-control-plane| jq -r '.[].NetworkSettings.Networks.kind.MacAddress' | awk '{gsub(/:/," "); print}')
worker_node_mac_bpf=$(docker inspect l3cni-two-node-worker| jq -r '.[].NetworkSettings.Networks.kind.MacAddress'| awk '{gsub(/:/," "); print}')

controller_node_eth0_index=$(docker exec l3cni-two-node-control-plane ip -o link show eth0 | awk -F': ' '{print $1}')

controller_node_eth0_index_bpf=$(bc <<< "obase=16; $controller_node_eth0_index")
worker_node_eth0_index=$(docker exec l3cni-two-node-worker ip -o link show eth0 | awk -F': ' '{print $1}')
worker_node_eth0_index_bpf=$(bc <<< "obase=16; $worker_node_eth0_index")

controller_pod_ips=()
worker_pod_ips=()

while IFS=' ' read -r ip_address node_name; do
  # Ensure consistent spacing for clarity
  if [ "$node_name" == "l3cni-two-node-control-plane" ]; then
    controller_pod_ips+=("$ip_address")
  elif [ "$node_name" == "l3cni-two-node-worker" ]; then
    worker_pod_ips+=("$ip_address")
  else
    echo "Unexpected node name: $node_name"  # Alert for unexpected values
  fi
done < <(kubectl get pods --all-namespaces -o custom-columns=IP:.status.podIP,NODE:.spec.nodeName | grep '10.240')

for ip in ${controller_pod_ips[@]}; do
    ip_bpf=$(echo "$ip" | awk '{gsub(/\./, " "); print}')
    docker exec l3cni-two-node-worker bpftool map update name forward_worker key $ip_bpf value hex $controller_node_mac_bpf 00 00 $worker_node_eth0_index_bpf 00 00 00
done

for ip in ${worker_pod_ips[@]}; do
    ip_bpf=$(echo "$ip" | awk '{gsub(/\./, " "); print}')
    docker exec l3cni-two-node-control-plane bpftool map update name forward_con key $ip_bpf value hex $worker_node_mac_bpf 00 00 $controller_node_eth0_index_bpf 00 00 00
done