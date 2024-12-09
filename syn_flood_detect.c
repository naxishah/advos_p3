#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Define a hash map to track SYN counts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} syn_map SEC(".maps");

// Define the perf event array for sending alerts
 struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 4); // Set to the number of CPUs
} events SEC(".maps");

// Structure for SYN flood alert
struct syn_event {
    __u32 src_ip;
    __u32 count;
};

SEC("xdp")
int detect_syn_flood(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && !tcp->ack) {
        __u32 src_ip = ip->saddr;
        __u32 *count, init_val = 1;

        count = bpf_map_lookup_elem(&syn_map, &src_ip);
        if (count) {
            (*count)++;
        } else {
            bpf_map_update_elem(&syn_map, &src_ip, &init_val, BPF_ANY);
        }

        if (count && *count > 100) { // Threshold for alert
            struct syn_event event = {
                .src_ip = src_ip,
                .count = *count,
            };
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
