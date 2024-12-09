#!/bin/bash

# Capsule Setup Script
# Creates two capsules with networking support

# Clean up existing namespaces and bridge
ip netns delete capsule1 2>/dev/null
ip netns delete capsule2 2>/dev/null
ip link delete br0 2>/dev/null

# Create network namespaces
ip netns add capsule1
ip netns add capsule2

# Create veth pairs
ip link add veth1 type veth peer name veth1-br
ip link add veth2 type veth peer name veth2-br

# Assign one end of each veth pair to the capsules
ip link set veth1 netns capsule1
ip link set veth2 netns capsule2

# Bring up the bridge and veth interfaces
ip link add br0 type bridge
ip link set br0 up
ip link set veth1-br up
ip link set veth2-br up
brctl addif br0 veth1-br
brctl addif br0 veth2-br

# Configure capsule1
ip netns exec capsule1 ip link set lo up
ip netns exec capsule1 ip link set veth1 up
ip netns exec capsule1 ip addr add 192.168.1.2/24 dev veth1

# Configure capsule2
ip netns exec capsule2 ip link set lo up
ip netns exec capsule2 ip link set veth2 up
ip netns exec capsule2 ip addr add 192.168.1.3/24 dev veth2

# Add IP address to the bridge for external access
ip addr add 192.168.1.1/24 dev br0
echo "Capsules setup completed!"
