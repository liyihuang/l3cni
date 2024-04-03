#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#include "bpf_endian.h"



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

    bpf_printk("src ip is %x and dst ip is %x", ip->saddr, ip->daddr);
    bpf_printk("what I wrote is src ip is %x and dst ip is %x", bpf_htonl(0x7F000001), bpf_htonl(0x7F000001));

    if (ip->saddr == bpf_htonl(0x7F000001) && ip->daddr == bpf_htonl(0x7F000001)){
        
        bpf_printk("mathcing");
        return bpf_redirect(5,BPF_F_INGRESS);
    }

    return TC_ACT_OK;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
