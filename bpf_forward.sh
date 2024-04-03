clang -g -O2 -target bpf -Wall -c bpf_forward.c -I./headers -o bpf_forward.o
sudo tc qdisc add dev lo clsact
sudo tc filter add dev lo ingress bpf da obj bpf_forward.o sec ingress
sudo cat /sys/kernel/debug/tracing/trace_pipe


sudo tc qdisc del dev lo clsact