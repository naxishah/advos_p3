#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAP_PATH "/sys/fs/bpf/ip_count_map"

int main() {
    int map_fd = bpf_map_get_fd_by_id(6);
    if (map_fd < 0) {
        perror("Failed to open BPF map");
        return 1;
    }

    __u32 key = 0, next_key;
    __u64 value;

    printf("Source IP Address      Packet Count\n");
    printf("-----------------------------------\n");

    while (1) {
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &next_key, ip, INET_ADDRSTRLEN);
                printf("%-20s %llu\n", ip, value);
            }
            key = next_key;
        }
        sleep(1); // Poll every second
        key = 0;
    }

    close(map_fd);
    return 0;
}
