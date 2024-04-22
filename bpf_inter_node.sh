#!/bin/bash
set -euo pipefail

echo "get the node MAC and eth0 index in bytes format so we can update the bpf map easily"

controller_node_mac_bpf=$(docker inspect l3cni-two-node-control-plane| jq -r '.[].NetworkSettings.Networks.kind.MacAddress' | awk '{gsub(/:/," "); print}')
worker_node_mac_bpf=$(docker inspect l3cni-two-node-worker| jq -r '.[].NetworkSettings.Networks.kind.MacAddress'| awk '{gsub(/:/," "); print}')

controller_node_eth0_index=$(docker exec l3cni-two-node-control-plane ip -o link show eth0 | awk -F': ' '{print $1}')

controller_node_eth0_index_bpf=$(printf "%08x" $controller_node_eth0_index | sed -r 's/(..)(..)(..)(..)/\4 \3 \2 \1/')
worker_node_eth0_index=$(docker exec l3cni-two-node-worker ip -o link show eth0 | awk -F': ' '{print $1}')
worker_node_eth0_index_bpf=$(printf "%08x" $worker_node_eth0_index | sed -r 's/(..)(..)(..)(..)/\4 \3 \2 \1/')

controller_pod_ips=()
worker_pod_ips=()

echo "find all pods allocated IP address by CNI to a list "
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

echo "update the bpfmap on worker so they know how to reach pods on the controller"
for ip in ${controller_pod_ips[@]}; do
    ip_bpf=$(echo "$ip" | awk '{gsub(/\./, " "); print}')
    docker exec l3cni-two-node-worker bpftool map update name forward_worker key $ip_bpf value hex $controller_node_mac_bpf 00 00 $worker_node_eth0_index_bpf
done

echo "update the bpfmap on controller so they know how to reach pods on the worker"
for ip in ${worker_pod_ips[@]}; do
    ip_bpf=$(echo "$ip" | awk '{gsub(/\./, " "); print}')
    docker exec l3cni-two-node-control-plane bpftool map update name forward_con key $ip_bpf value hex $worker_node_mac_bpf 00 00 $controller_node_eth0_index_bpf
done