Please Note that for eBPF development, you may need to get these packages:
sudo apt-get install clang llvm libelf-dev gcc-multilib

# Question 1 
## Compile the program 
make

## Verify the module
ls -l capsule_comm.ko

## Load the Kernel Module 
sudo insmod capsule_comm.ko

## Verify that the module is loaded
lsmod | grep capsule_comm

## Check the kernel logs
sudo dmesg | tail -20

## Unload the Kernel Module
sudo rmmod capsule_comm

## Make the script executable
chmod +x setup_capsules.sh

## Run the script
sudo ./setup_capsules.sh

## Verify capsules
ip netns list

## Compile the test program
gcc internet_test.c -o internet_test

## Run the program in capsule1
sudo ip netns exec capsule1 ./internet_test

## Compile the server: 
gcc tcp_server.c -o tcp_server

## Compile the client: 
gcc tcp_client.c -o tcp_client

## Run the TCP Server
sudo ip netns exec capsule1 ./tcp_server

## Run the TCP Client
sudo ip netns exec capsule2 ./tcp_client

# Question 2 Part A
## Compile the program
clang -O2 -g -target bpf -c count_packets.c -o count_packets.o

## Detach existing XDP program (if any)
sudo ip link set dev enp0s3 xdp off

## Attach the new program
sudo ip link set dev enp0s3 xdp obj count_packets.o

## Verify attachment
sudo ip link show dev enp0s3

## Generate network traffic
ping -c 5 8.8.8.8

## Convert raw keys to human-readable IPs
python3 -c 'import socket, struct; print(socket.inet_ntoa(struct.pack("<I", 296598804)))'  # Replace with actual key

## Compile the Userspace Program
gcc -o count_packets_user count_packets_user.c -lbpf

## Run the Userspace Program
sudo ./count_packets_user

## (Optional) Check kernel logs
sudo dmesg | tail -n 50

## Detach the program when done
sudo ip link set dev enp0s3 xdp off

# Question 2 Part B
## Create bpftool map 
sudo bpftool map create /sys/fs/bpf/events type perf_event_array name test_events key 4 value 4 entries 4

## Compile the eBPF program
clang -O2 -g -target bpf -c syn_flood_detect.c -o syn_flood_detect.o

## Attach the program to the interface
sudo ip link set dev enp0s3 xdp obj syn_flood_detect.o sec xdp

## Verify the program is attached
sudo ip link show dev enp0s3

## Compile the userspace program
gcc -o syn_flood_user syn_flood_user.c -lbpf

## Run the userspace program
sudo ./syn_flood_user

## In a new terminal, generate SYN packets using hping3
sudo apt install hping3
sudo hping3 -S -p 80 -c 200 <target_IP>

## Check kernel logs if no output is seen
sudo dmesg | tail -n 50

## Detach the XDP program
sudo ip link set dev enp0s3 xdp off

## Verify detachment
sudo ip link show dev enp0s3

# Question 3 Part A 
## Install dependencies:
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev linux-headers-$(uname -r) bpftool

## Compile load_balancer.c:
clang -g -O2 -target bpf -c load_balancer.c -o load_balancer.o -I/home/naxi/Desktop/pa3/libbpf/src

## Compile load_balancer_user.c:
gcc -o load_balancer_user load_balancer_user.c -lbpf -lelf -lz

## Run the program:
sudo ./load_balancer_user enp0s3

## Verify attachment:
ip link show dev enp0s3

## Inspect the object file:
llvm-readelf --sections load_balancer.o | grep BTF

## Debug:
### Check logs:
dmesg | tail
### Inspect loaded programs:
sudo bpftool prog show

# Expected Outputs 
## Question 1 
### On the server (capsule1):
Server listening on port 12345...
Client connected from 192.168.1.3:xxxxx
### On the client (capsule2):
Connected to the server successfully

## Question 2 Part A
naxi@naxi-VirtualBox:~/Desktop/pa3$ gcc -o count_packets_user count_packets_user.c -lbpf
naxi@naxi-VirtualBox:~/Desktop/pa3$ sudo ./count_packets_user
Source IP Address      Packet Count
-----------------------------------
20.189.173.17        1
152.199.4.33         5
104.18.32.47         746
10.0.2.3             4
20.189.173.17        1
152.199.4.33         5
104.18.32.47         746
10.0.2.3             4
20.189.173.17        1
152.199.4.33         5
104.18.32.47         746
10.0.2.3             4
20.189.173.17        1
152.199.4.33         5
104.18.32.47         746
10.0.2.3             4

## Question 3 Part A
naxi@naxi-VirtualBox:~/Desktop/pa3$ clang -g -O2 -target bpf -c load_balancer.c -o load_balancer.o \
  -I/home/naxi/Desktop/pa3/libbpf/src
naxi@naxi-VirtualBox:~/Desktop/pa3$ gcc -o load_balancer_user load_balancer_user.c -lbpf -lelf -lz
naxi@naxi-VirtualBox:~/Desktop/pa3$ sudo ./load_balancer_user enp0s3
eBPF load balancer attached to interface enp0s3
naxi@naxi-VirtualBox:~/Desktop/pa3$ llvm-readelf --sections load_balancer.o | grep BTF
  [16] .BTF              PROGBITS        0000000000000000 000e34 000658 00      0   0  4
  [17] .rel.BTF          REL             0000000000000000 002190 000030 10   I 26  16  8
  [18] .BTF.ext          PROGBITS        0000000000000000 00148c 000210 00      0   0  4
  [19] .rel.BTF.ext      REL             0000000000000000 0021c0 0001e0 10   I 26  18  8
naxi@naxi-VirtualBox:~/Desktop/pa3$ sudo ./load_balancer_user enp0s3
eBPF load balancer attached to interface enp0s3
naxi@naxi-VirtualBox:~/Desktop/pa3$ 
