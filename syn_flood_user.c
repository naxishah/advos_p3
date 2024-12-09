#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Event structure
struct syn_event {
    __u32 src_ip;
    __u32 count;
};

// Event handler
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct syn_event *event = data;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &event->src_ip, ip, INET_ADDRSTRLEN);
    printf("SYN flood detected from IP %s, count: %u\n", ip, event->count);
}

// Lost events handler
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main() {
    struct perf_buffer *pb;
    int map_fd;

    // Open the pinned 'events' map
    map_fd = bpf_obj_get("/sys/fs/bpf/events");
    if (map_fd < 0) {
        perror("Failed to open BPF map");
        return 1;
    }

    // Set up the perf buffer
    //pb = perf_buffer__new(map_fd, 128, handle_event, handle_lost_events, NULL);
    pb = perf_buffer__new(map_fd, 128, handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to set up perf buffer\n");
        return 1;
    }

    // Poll for events
    while (1) {
        int err = perf_buffer__poll(pb, 1000 /* timeout in ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);
    return 0;
}

