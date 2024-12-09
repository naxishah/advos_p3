#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#define PROC_FILENAME "capsule_comm"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Capsule Communication Module");

static struct proc_dir_entry *proc_file;

// Buffer for user-space input
#define MAX_INPUT_SIZE 256
static char user_input[MAX_INPUT_SIZE];

static ssize_t capsule_comm_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {
    char *msg = "Capsule Communication Module: Write capsule ID and address to configure communication.\n";
    size_t msg_len = strlen(msg);

    if (*offset >= msg_len) {
        return 0; // EOF
    }

    if (len > msg_len - *offset) {
        len = msg_len - *offset;
    }

    if (copy_to_user(buffer, msg + *offset, len)) {
        return -EFAULT;
    }

    *offset += len;
    return len;
}

static ssize_t capsule_comm_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    if (len > MAX_INPUT_SIZE - 1) {
        return -EINVAL; // Input too long
    }

    if (copy_from_user(user_input, buffer, len)) {
        return -EFAULT;
    }

    user_input[len] = '\0'; // Null-terminate the input

    printk(KERN_INFO "Capsule Communication Module: Received input: %s\n", user_input);

    // Simulate parsing capsule ID and address
    int capsule_id;
    char ip[16];
    int port;

    if (sscanf(user_input, "%d %15s %d", &capsule_id, ip, &port) == 3) {
        printk(KERN_INFO "Capsule ID: %d, IP: %s, Port: %d\n", capsule_id, ip, port);
    } else {
        printk(KERN_ERR "Invalid input format. Expected: <capsule_id> <ip> <port>\n");
    }

    return len;
}

static const struct proc_ops capsule_comm_fops = {
    .proc_read = capsule_comm_read,
    .proc_write = capsule_comm_write,
};

static int __init capsule_comm_init(void) {
    proc_file = proc_create(PROC_FILENAME, 0666, NULL, &capsule_comm_fops);
    if (!proc_file) {
        printk(KERN_ERR "Failed to create /proc/%s\n", PROC_FILENAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "Capsule Communication Module Loaded: /proc/%s created\n", PROC_FILENAME);
    return 0;
}

static void __exit capsule_comm_exit(void) {
    proc_remove(proc_file);
    printk(KERN_INFO "Capsule Communication Module Unloaded\n");
}

module_init(capsule_comm_init);
module_exit(capsule_comm_exit);
