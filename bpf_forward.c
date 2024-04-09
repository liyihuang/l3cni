#include <string.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct dst_mac_if {
unsigned char dest_mac[ETH_ALEN];
__u32 ifindex;
};

struct {
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries, 100);
__type(key, __u32);
__type(value,struct dst_mac_if);
} bpf_forward SEC(".maps");

struct reply_mac_if {
unsigned char reply_src_mac[ETH_ALEN];
__u32 reply_if_index;
};

struct {
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries, 100);
__type(key, __u32);
__type(value,struct reply_mac_if);
} proxy_arp SEC(".maps");

__attribute__((section("ingress"), used))
int drop_src_dst_ip(struct __sk_buff *skb) {
    const int l2_header = ETH_HLEN;
    const int arp_length = 28;
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    if (data_end < data + l2_header)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (eth->h_proto == bpf_htons(ETH_P_ARP)){ 
        if (data_end < data + l2_header+arp_length)
            return TC_ACT_OK;

        bpf_printk("it's an ARP");
        __be32 sip = *(__be32*)(data+l2_header+14);
        __be32 tip = *(__be32*)(data+l2_header+24);
        
        unsigned char reply_src_mac[ETH_ALEN];
        bpf_printk("sip is %x ",sip);
        struct reply_mac_if *result = bpf_map_lookup_elem(&proxy_arp, &(sip));
        if (result)
            memcpy(&reply_src_mac,&result->reply_src_mac,ETH_ALEN);
        else{
            bpf_printk("not our ARP request, giving back to kernel");
            return TC_ACT_OK;
        }

        unsigned char reply_dst_mac[ETH_ALEN];
        memcpy(&reply_dst_mac, &eth->h_source, ETH_ALEN);
        __be16 arpop = bpf_htons(ARPOP_REPLY);

        if (
            bpf_skb_store_bytes(skb, 0, &reply_dst_mac, ETH_ALEN, 0) < 0 ||
            bpf_skb_store_bytes(skb, 6, &reply_src_mac, ETH_ALEN, 0) < 0 ||
            bpf_skb_store_bytes(skb, 20, &arpop, sizeof(arpop), 0) < 0 ||
            bpf_skb_store_bytes(skb, 22, &reply_src_mac, ETH_ALEN, 0) < 0 ||
	        bpf_skb_store_bytes(skb, 28, &tip, sizeof(tip), 0) < 0 ||
	        bpf_skb_store_bytes(skb, 32, &reply_dst_mac, ETH_ALEN, 0) < 0 ||
	        bpf_skb_store_bytes(skb, 38, &sip, sizeof(sip), 0) < 0
            )
            return -1;
        else
            bpf_printk("it's redirecting to %d",result->reply_if_index);
            return bpf_redirect(result->reply_if_index,0);
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP) || data_end < data + l2_header + sizeof( struct iphdr))
       return TC_ACT_OK;

    bpf_printk("it's an normal IP packet");
    struct iphdr *ip = (struct iphdr *)(data + l2_header);
    struct dst_mac_if *result = bpf_map_lookup_elem(&bpf_forward, &(ip->daddr));
    if (result){
        memcpy(eth->h_dest,result->dest_mac,ETH_ALEN);
        bpf_printk("it's redirecting to %d",result->ifindex);
        return bpf_redirect(result->ifindex,0);
    }
    return TC_ACT_OK;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
