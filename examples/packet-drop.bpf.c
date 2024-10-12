#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP	0x0800		

// Returns the protocol byte for an IP packet, 0 for anything else
unsigned char lookup_protocol(struct xdp_md *ctx)
{
    unsigned char protocol = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) 
    {
        return 0;
    }

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP        
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end) 
        {
            protocol = iph->protocol;
        }
    }
    return protocol;
}


SEC("xdp")
int ping_handler(struct xdp_md *ctx) {
    long protocol = lookup_protocol(ctx);
    if (protocol == 1) // ICMP 
    {
        bpf_printk("Received ICMP packet");
        // return XDP_DROP; 
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
