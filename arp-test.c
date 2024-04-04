#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include <bpf/bpf_endian.h>


__attribute__((section("ingress"), used))
int arp_test(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;                      // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset

    bpf_printk("get to ebpf program");
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    if (data_end < data + l4_off)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
//    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (eth->h_proto == bpf_htons(ETH_P_ARP)){
        struct arphdr *arp = data+l3_off;
        bpf_printk("it's an ARP ");
        __be16 arpop = bpf_htons(ARPOP_REPLY);
 //       __be32 sip = bpf_htonl(0xC0A80101);
        unsigned char src_mac[6] = {0xe2, 0x52, 0x28, 0x1b, 0xc7, 0xdf};
        memcpy(eth->h_dest,eth->h_source,ETH_ALEN);
        memcpy(eth->h_source,src_mac,ETH_ALEN);
        memcpy(&arp->ar_op,&arpop,sizeof(arpop));
        bpf_printk("its redirecting");
        return bpf_redirect(5,BPF_F_INGRESS);



    }
    bpf_printk("pass to kernel");
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
