#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") bpf_match = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 100,
};

__attribute__((section("ingress"), used))
int bpf_firewall(struct __sk_buff *skb) {
    const int l2_header = ETH_HLEN;                      
    const int l2_l3_headers = l2_header + sizeof(struct iphdr); 

    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    if (data_end < data + l2_l3_headers)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
       return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(data + l2_header);
    __u32 *value = bpf_map_lookup_elem(&bpf_match, &(ip->saddr));
    if (value && ip->daddr == *value){
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
