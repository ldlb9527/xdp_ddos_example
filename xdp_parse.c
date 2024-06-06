//go:build ignore
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_vlan.h>


struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#define MAX_MAP_ENTRIES 16

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32); // source IPv4 address
    __type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32);
    __type(value, __u32);
} xdp_black_list_map SEC(".maps");


SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;

    __u64 nh_off = sizeof(*eth);

    eth = data;

    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    __u16 eth_type = eth->h_proto;
    if (eth_type != bpf_ntohs(ETH_P_IP)) {
        return XDP_PASS;
    }

    if (data + nh_off + sizeof(*iph) > data_end) {
        return XDP_PASS;
    }

    iph = data + nh_off;
    unsigned int sip = iph->saddr;

    __u32 *count = bpf_map_lookup_elem(&xdp_stats_map, &sip);
    if (count) {
        (*count) += 1;
    } else {
        __u32 init_pkt_count = 1;
        bpf_map_update_elem(&xdp_stats_map, &sip, &init_pkt_count, BPF_ANY);
    }

    __u32 *val = bpf_map_lookup_elem(&xdp_black_list_map, &sip);
    if (val) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


