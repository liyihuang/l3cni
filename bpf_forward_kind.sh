
docker exec l3cni-two-node-worker bpftool map update name proxy_arp_map key 10 240 1 2 value hex de 41 dd bd 3b e8 00 00 02 00 00 00
docker exec l3cni-two-node-worker bpftool map update name bpf_forward_map key 10 240 1 2 value hex ce 0c 02 4e a8 b0 00 00 02 00 00 00

docker exec l3cni-two-node-worker bpftool map update name proxy_arp_map key 10 240 1 3 value hex ae 7a a8 3c 5c 43 00 00 03 00 00 00
docker exec l3cni-two-node-worker bpftool map update name bpf_forward_map key 10 240 1 3 value hex ae 4d 5e b1 aa 1d 00 00 03 00 00 00
