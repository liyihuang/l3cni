#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

__attribute__((section("egress"), used))
int drop_src_dst_ip(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;                      // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset

    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    if (data_end < data + l4_off)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
       return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol != IPPROTO_ICMP)
        return TC_ACT_OK;

    if (ip->saddr != htonl(0xC0A8021C) && ip->daddr != htonl(0xC0A802C9)){
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";