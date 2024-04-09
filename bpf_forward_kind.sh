clang -g -O2 -target bpf -Wall -c bpf_forward.c -I./headers -o bpf_forward.o
docker cp bpf_forward.o l3cni-two-node-worker:/root

docker exec l3cni-two-node-worker tc qdisc del dev host-2 clsact
docker exec l3cni-two-node-worker tc qdisc add dev host-2 clsact
docker exec l3cni-two-node-worker tc filter add dev host-2 ingress bpf da obj /root/bpf_forward.o sec ingress

docker exec l3cni-two-node-worker bpftool map update name proxy_arp key 10 240 1 2 value hex 9e b7 ae d5 c8 c7 00 00 02 00 00 00
docker exec l3cni-two-node-worker bpftool map update name bpf_forward key 10 240 1 3 value hex ae 4d 5e b1 aa 1d 00 00 03 00 00 00

docker exec l3cni-two-node-worker tc qdisc del dev host-3 clsact
docker exec l3cni-two-node-worker tc qdisc add dev host-3 clsact
docker exec l3cni-two-node-worker tc filter add dev host-3 ingress bpf da obj /root/bpf_forward.o sec ingress

docker exec l3cni-two-node-worker bpftool map update id 825 key 10 240 1 3 value hex ae 7a a8 3c 5c 43 00 00 03 00 00 00
docker exec l3cni-two-node-worker bpftool map update id 826 key 10 240 1 2 value hex b6 54 7d 43 4f 81 00 00 02 00 00 00