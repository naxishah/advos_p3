#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/clone.h>

struct container_info {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 namespace_id;
};

BPF_PERF_OUTPUT(container_events);

int trace_clone(struct pt_regs *ctx) {
    u64 flags = (u64)PT_REGS_PARM2(ctx);  // flags argument to clone syscall
    if (flags & (CLONE_NEWNS | CLONE_NEWPID)) {  // Check for new namespaces
        struct container_info info = {};
        info.pid = bpf_get_current_pid_tgid() >> 32;  // PID
        bpf_get_current_comm(info.comm, sizeof(info.comm));  // Command name

        // Accessing task struct directly for namespaces
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        
        // Get the namespace ID for mount or PID namespace
        if (flags & CLONE_NEWNS) {
            info.namespace_id = task->mnt_ns->inum;  // Mount namespace inode number
        } else if (flags & CLONE_NEWPID) {
            info.namespace_id = task->pid_ns->ns.inum;  // PID namespace inode number
        }

        container_events.perf_submit(ctx, &info, sizeof(info));  // Send data to user space
    }
    return 0;
}
