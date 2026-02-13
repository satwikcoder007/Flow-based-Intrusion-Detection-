#!/bin/bash
set -euo pipefail

# echo "[*] Enabling IP forwarding"
# sysctl -w net.ipv4.ip_forward=1

# echo "[*] Setting up NAT"
# iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || \
# iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Create output directories
mkdir -p ${PCAP_DIR} ${FLOW_DIR} ${FLOW_ARCHIVE_DIR} ${RESULT_DIR}

echo "[*] Starting packet capture (Rotating every 15 seconds)"
# -G 15: Rotate file every 60 seconds
# -w ..._%S.pcap: Ensures unique filenames based on timestamp
tcpdump -i eth0 -s 0 -G 60 -U -w ${PCAP_DIR}/traffic_%Y%m%d%H%M%S.pcap -Z root &
TCPDUMP_PID=$!

# Brief pause to let tcpdump initialize
sleep 2

echo "[*] Starting Gateway & IDS"
python3 gateway.py &
GATEWAY_PID=$!

trap "echo '[*] Stopping...'; kill $TCPDUMP_PID $GATEWAY_PID" SIGTERM SIGINT

wait