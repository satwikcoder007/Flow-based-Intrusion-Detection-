import socket
import struct
import time
import random
import os
import signal
import threading
import logging

# Gateway config
GATEWAY_IP = os.getenv("GATEWAY_IP", "172.30.0.2")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 9999))

# Random sleep
SLEEP_LL = 0.5
SLEEP_UL = 3.0

# Sensor config
TEMP_LL = 20.0
TEMP_UL = 30.0

HUM_LL = 40.0
HUM_UL = 60.0

# Protocol Definitions
HEADER_FMT = "!I"
PAYLOAD_FMT = "!Q f f"
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FMT)

shutdown_event = threading.Event()

# Setup Logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)


def generate_frame():
    """Packs Length Header + Payload"""
    payload = struct.pack(
        PAYLOAD_FMT,
        time.time_ns(),
        random.uniform(TEMP_LL, TEMP_UL),
        random.uniform(HUM_LL, HUM_UL),
    )
    header = struct.pack(HEADER_FMT, PAYLOAD_SIZE)
    return header + payload


def main():
    signal.signal(signal.SIGTERM, lambda s, f: shutdown_event.set())
    signal.signal(signal.SIGINT, lambda s, f: shutdown_event.set())

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((GATEWAY_IP, GATEWAY_PORT))
            sock.settimeout(1.0)

            logging.info("[+] Connected to gateway")

            while not shutdown_event.is_set():
                frame = generate_frame()
                try:
                    sock.sendall(frame)
                except (BrokenPipeError, ConnectionResetError):
                    logging.error("[!] Gateway disconnected")
                    break

                time.sleep(random.uniform(SLEEP_LL, SLEEP_UL))

    except Exception as e:
        logging.error(f"[!] Fatal error: {e}")

    logging.info("[*] Device shutdown complete")


if __name__ == "__main__":
    main()
