#!/bin/bash
kind create cluster --config=kind-l3cni-two-node.yaml
kubectl taint nodes l3cni-two-node-control-plane node-role.kubernetes.io/control-plane-

control_node_podcidr=$(kubectl get nodes l3cni-two-node-control-plane  -o json | jq -r '.spec.podCIDR')
control_node_gw_ip=$(echo "$control_node_podcidr" | sed "s:\.0/24:.1:")
control_node_ip=$(kubectl get nodes l3cni-two-node-control-plane -o json | jq -r '.status.addresses[] | select(.type == "InternalIP") | .address')


worker_node_podcidr=$(kubectl get nodes l3cni-two-node-worker  -o json | jq -r '.spec.podCIDR')
worker_node_gw_ip=$(echo "$worker_node_podcidr" | sed "s:\.0/24:.1:")
worker_node_ip=$(kubectl get nodes l3cni-two-node-worker -o json | jq -r '.status.addresses[] | select(.type == "InternalIP") | .address')

jq --arg control_node_podcidr "$control_node_podcidr" \
--arg control_node_gw_ip "$control_node_gw_ip" \
--arg worker_node_podcidr "$worker_node_podcidr" \
--arg worker_node_ip "$worker_node_ip" \
'.podcidr = $control_node_podcidr |
    .peer_net = $worker_node_podcidr |
    .peer_ip = $worker_node_ip' 10-l3cni-control.conf > tmp_config.json && mv tmp_config.json 10-l3cni-control.conf


jq --arg worker_node_podcidr "$worker_node_podcidr" \
--arg worker_node_gw_ip "$worker_node_gw_ip" \
--arg control_node_podcidr "$control_node_podcidr" \
--arg control_node_ip "$control_node_ip" \
'.podcidr = $worker_node_podcidr |
    .peer_net = $control_node_podcidr |
    .peer_ip = $control_node_ip' 10-l3cni-worker.conf > tmp_config.json && mv tmp_config.json 10-l3cni-worker.conf

docker cp 10-l3cni-control.conf  l3cni-two-node-control-plane:/etc/cni/net.d/
docker cp 10-l3cni-worker.conf  l3cni-two-node-worker:/etc/cni/net.d/


if [ "$1" == "" ]; then
    docker cp l3cni  l3cni-two-node-control-plane:/opt/cni/bin/
    docker cp l3cni  l3cni-two-node-worker:/opt/cni/bin/
elif [ "$1" == "bpf" ]; then
    docker cp l3cni_bpf  l3cni-two-node-control-plane:/opt/cni/bin/l3cni
    docker cp l3cni_bpf  l3cni-two-node-worker:/opt/cni/bin/l3cni

fi

kubectl run  busyboxc1 --image=curlimages/curl --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-control-plane" }}}' -- sleep infinity
kubectl run  busyboxc2 --image=nginx:stable-alpine3.17-slim --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-control-plane" }}}'
kubectl run  busyboxc3 --image=nginx:stable-alpine3.17-slim --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-control-plane" }}}'
kubectl run  busyboxw1 --image=curlimages/curl --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-worker" }}}' -- sleep infinity
kubectl run  busyboxw2 --image=nginx:stable-alpine3.17-slim --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-worker" }}}'


