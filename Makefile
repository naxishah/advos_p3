# Specify the kernel module to be built
obj-m += capsule_comm.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current working directory
PWD := $(shell pwd)

# Build the kernel module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean build files
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Load the kernel module
load: all
	sudo insmod capsule_comm.ko

# Unload the kernel module
unload:
	sudo rmmod capsule_comm

# Show kernel logs
log:
	dmesg | tail -20
