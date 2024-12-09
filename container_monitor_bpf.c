#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>
//#include <linux/clone.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct container_event {
    int pid;
    char comm[16];
    __aligned_u64 namespace_id;
};

// Define the eBPF program that attaches to the clone syscall
SEC("kprobe/clone")
int monitor_container_start(struct pt_regs *ctx) {
    // Check if the clone flags indicate new namespaces are being created
    unsigned long flags = (unsigned long)PT_REGS_PARM1(ctx);
    if (flags & (CLONE_NEWNS | CLONE_NEWPID)) {
        struct container_event event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32; // Get PID
        bpf_get_current_comm(event.comm, sizeof(event.comm)); // Get command name
        
        // Capture namespace flags as needed
        event.namespace_id = flags; // Example: Capture the namespace flag

        // Output the event to trace_pipe or a BPF ring buffer
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
