#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define MAX_BACKENDS 4

// Map for storing backend IPs
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u32);
} backend_ips SEC(".maps");

// XDP Program for Load Balancing using Consistent Hashing
SEC("xdp")
int xdp_load_balancer_chash(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Check if it's an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Only handle TCP or UDP traffic
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Hash the source IP to determine the backend server
    __u32 src_ip = ip->saddr;
    __u32 backend_index = src_ip % MAX_BACKENDS;

    // Lookup the backend IP based on the hash
    __u32 *backend_ip = bpf_map_lookup_elem(&backend_ips, &backend_index);
    if (!backend_ip)
        return XDP_DROP;

    // Update destination IP to the selected backend server
    ip->daddr = *backend_ip;

    // Recalculate IP checksum
    ip->check = 0;
    ip->check = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(struct iphdr), 0);

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
