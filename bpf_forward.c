#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include "bpf_endian.h"

struct dst_mac_if {
__u32 ifindex;
unsigned char h_dest[ETH_ALEN];
};


struct {
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries, 100);
__type(key, __u32);
__type(value,struct dst_mac_if);
} bpf_forward SEC(".maps");

__attribute__((section("ingress"), used))
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
    struct dst_mac_if *result = bpf_map_lookup_elem(&bpf_forward, &(ip->daddr));
    if (result){
        memcpy(eth->h_dest,result->h_dest,ETH_ALEN);
        return bpf_redirect(result->ifindex,0);
    }
    return TC_ACT_OK;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
