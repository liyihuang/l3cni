src_ip=$(kubectl get pods busyboxc1 -o json | jq -r '.status.podIP')
dst_ip=$(kubectl get pods busyboxc2 -o json | jq -r '.status.podIP')

docker exec l3cni-two-node-control-plane iptables -A FORWARD -s $src_ip -d $dst_ip -j DROP
