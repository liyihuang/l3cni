#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include <bpf/bpf_endian.h>
#include <linux/if_arp.h>


__attribute__((section("ingress"), used))
int arp_test(struct __sk_buff *skb) {
    //bpf_printk("get to ebpf program");
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    const int l2_header = ETH_HLEN;                      // IP header offset

    if (data_end < data + l2_header)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    if (eth->h_proto == bpf_htons(ETH_P_ARP)){ 
        if (data_end < data + l2_header+28)
            return TC_ACT_OK;
        __be32 sip = *(__be32*)(data+l2_header+14);
        __be32 dip = *(__be32*)(data+l2_header+24);
        bpf_printk("sip is %x",sip);
        bpf_printk("dip is %x",dip);

        unsigned char src_mac[ETH_ALEN] = {0xe2, 0x52, 0x28, 0x1b, 0xc7, 0xdf};

        unsigned char dst_mac[ETH_ALEN];
        memcpy(&dst_mac, &eth->h_source, ETH_ALEN);

        __be16 arpop = bpf_htons(ARPOP_REPLY);

        if (
            bpf_skb_store_bytes(skb, 0, &dst_mac, ETH_ALEN, 0) < 0 ||
            bpf_skb_store_bytes(skb, 6, &src_mac, ETH_ALEN, 0) < 0 ||
            bpf_skb_store_bytes(skb, 20, &arpop, sizeof(arpop), 0) < 0 ||
            bpf_skb_store_bytes(skb, 22, &src_mac, ETH_ALEN, 0) < 0 ||
	        bpf_skb_store_bytes(skb, 28, &sip, 4, 0) < 0 ||
	        bpf_skb_store_bytes(skb, 32, &dst_mac, ETH_ALEN, 0) < 0 ||
	        bpf_skb_store_bytes(skb, 38, &dip, 4, 0) < 0
            )
            return -1;
        else
            //bpf_printk("its redirecting");
            return bpf_redirect(5,0);
    }
    //bpf_printk("pass to kernel");
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

