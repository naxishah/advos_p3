#include <linux/bpf.h>
#include <linux/tracepoint.h>
#include <linux/netdevice.h>
#include <linux/nsproxy.h>

struct network_traffic {
    u32 pid;
    u64 ingress_bytes;
    u64 egress_bytes;
};

BPF_PERF_OUTPUT(network_traffic_events);

int track_ingress(struct trace_event_raw_netif_receive_skb *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = task->nsproxy;

    if (ns->net_ns->ns.inum == YOUR_NET_NAMESPACE_ID) {
        struct network_traffic info = {};
        info.pid = bpf_get_current_pid_tgid() >> 32;  // PID
        info.ingress_bytes = ctx->skb->len;  // Ingress bytes

        network_traffic_events.perf_submit(ctx, &info, sizeof(info));  // Send data to user space
    }
    return 0;
}

int track_egress(struct trace_event_raw_net_dev_queue *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = task->nsproxy;

    if (ns->net_ns->ns.inum == YOUR_NET_NAMESPACE_ID) {
        struct network_traffic info = {};
        info.pid = bpf_get_current_pid_tgid() >> 32;  // PID
        info.egress_bytes = ctx->skb->len;  // Egress bytes

        network_traffic_events.perf_submit(ctx, &info, sizeof(info));  // Send data to user space
    }
    return 0;
}
