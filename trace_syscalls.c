#include <linux/bpf.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>

struct syscall_info {
    u32 pid;
    u64 syscall_id;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(syscall_events);

int trace_syscalls(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = task->nsproxy;

    // Filter by PID or cgroup namespace (add condition for specific container)
    if (ns->pid_ns->ns.inum == YOUR_PID_NAMESPACE_ID) {
        struct syscall_info info = {};
        info.pid = bpf_get_current_pid_tgid() >> 32;  // PID
        info.syscall_id = ctx->id;
        bpf_get_current_comm(info.comm, sizeof(info.comm));  // Command name

        syscall_events.perf_submit(ctx, &info, sizeof(info));  // Send data to user space
    }
    return 0;
}
