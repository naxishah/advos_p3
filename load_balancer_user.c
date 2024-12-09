#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#define MAX_BACKENDS 4

int attach_xdp_program(int ifindex, int prog_fd, __u32 flags) {
    struct sockaddr_nl sa = {0};
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifinfo;
        char buf[128];
    } req = {0};

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    sa.nl_family = AF_NETLINK;

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = ifindex;

    struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFLA_XDP;
    rta->rta_len = RTA_LENGTH(sizeof(int));
    *(int *)RTA_DATA(rta) = prog_fd;
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(sizeof(int));

    if (sendto(sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}


int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char *iface = argv[1];
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, map_fd, rr_fd;
    int err;

    obj = bpf_object__open_file("load_balancer.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open eBPF object file\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load eBPF program\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_load_balancer");
    if (!prog) {
        fprintf(stderr, "Failed to find the eBPF program\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    map_fd = bpf_object__find_map_fd_by_name(obj, "backend_ips");
    rr_fd = bpf_object__find_map_fd_by_name(obj, "rr_index");

    if (map_fd < 0 || rr_fd < 0) {
        fprintf(stderr, "Failed to get map FDs\n");
        return 1;
    }

    __u32 backend_ips[MAX_BACKENDS] = {
        inet_addr("192.168.1.2"),
        inet_addr("192.168.1.3"),
        inet_addr("192.168.1.4"),
        inet_addr("192.168.1.5"),
    };

    for (__u32 i = 0; i < MAX_BACKENDS; i++) {
        err = bpf_map_update_elem(map_fd, &i, &backend_ips[i], BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update backend IPs for key %u\n", i);
            return 1;
        }
    }

    __u32 key = 0, initial_value = 0;
    err = bpf_map_update_elem(rr_fd, &key, &initial_value, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to initialize round-robin index\n");
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex failed");
        return 1;
    }

    err = attach_xdp_program(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to interface\n");
        return 1;
    }

    printf("eBPF load balancer attached to interface %s\n", iface);
    return 0;
}
