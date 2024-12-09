#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define MAX_BACKENDS 4

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u32);
} backend_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} rr_index SEC(".maps");

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 key = 0;
    __u32 *index = bpf_map_lookup_elem(&rr_index, &key);
    if (!index)
        return XDP_DROP;

    __u32 *backend_ip = bpf_map_lookup_elem(&backend_ips, index);
    if (!backend_ip)
        return XDP_DROP;

    __u32 next_index = (*index + 1) % MAX_BACKENDS;
    bpf_map_update_elem(&rr_index, &key, &next_index, BPF_ANY);

    ip->check = bpf_csum_diff(&ip->daddr, sizeof(ip->daddr), backend_ip, sizeof(*backend_ip), ip->check);
    ip->daddr = *backend_ip;

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
