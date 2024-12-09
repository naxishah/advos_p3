#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} ip_count_map SEC(".maps");

SEC("prog")
int count_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 *value, init_val = 1;

    value = bpf_map_lookup_elem(&ip_count_map, &src_ip);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        bpf_map_update_elem(&ip_count_map, &src_ip, &init_val, BPF_ANY);
    }

    // Optional: Log source IP and packet count to kernel logs
    bpf_printk("Source IP: %x, Count: %llu\n", src_ip, value ? *value : 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
