#include "vmlinux.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "if_ether_defs.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct {
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries, 100);
__type(key, __u32);
__type(value, __u32);
} bpf_match SEC(".maps");

__attribute__((section("egress"), used))
int drop_src_dst_ip(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;                      // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset

    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    if (data_end < data + l4_off)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
       return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    __u32 *value = bpf_map_lookup_elem(&bpf_match, &(ip->saddr));
    if (value && ip->daddr == *value){
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
