clang -g -O2 -target bpf -Wall -c bpf_firewall.c -I./headers -o bpf_firewall.o

src_ip=$(kubectl get pods busyboxc1 -o json | jq -r '.status.podIP' | sed 's/\./ /g')
dst_ip=$(kubectl get pods busyboxc2 -o json | jq -r '.status.podIP' | sed 's/\./ /g')
host_interface=$(echo "$src_ip" | awk '{print $NF}')


docker exec l3cni-two-node-control-plane apt update 
docker exec l3cni-two-node-control-plane apt install bpftool -y 
docker cp bpf_firewall.o l3cni-two-node-control-plane:/root


docker exec l3cni-two-node-control-plane tc qdisc add dev host-"$host_interface" clsact
docker exec l3cni-two-node-control-plane tc filter add dev host-"$host_interface" egress bpf da obj /root/bpf_firewall.o sec egress
docker exec l3cni-two-node-control-plane bpftool map update name bpf_match key "$src_ip" value "$dst_ip"


