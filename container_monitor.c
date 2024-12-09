#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
//#include "container_monitor_bpf.skel.h"  // Include the correct BPF skeleton header

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct container_monitor_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    // Open BPF application
    skel = container_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = container_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attach tracepoint handler
    err = container_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    // Event loop to print container events
    for (;;) {
        // Event handling logic to process BPF outputs (container creation data)
        // This will print the PID, command name, and namespace ID as captured by BPF
        sleep(1);
    }

cleanup:
    container_monitor_bpf__destroy(skel);
    return -err;
}
