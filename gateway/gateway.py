import selectors
import shutil
import signal
import socket
import struct
import os
import threading
import time
import glob
import subprocess
import pandas as pd
import logging
import joblib
import collections

# --- Configuration ---
GATEWAY_IP = os.getenv("GATEWAY_IP", "172.30.0.2")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 9999))
PCAP_DIR = os.getenv("PCAP_DIR", "/app/data/pcaps")
FLOW_DIR = os.getenv("FLOW_DIR", "/app/data/flows")
FLOW_ARCHIVE_DIR = os.getenv("FLOW_ARCHIVE_DIR", "/app/data/flows_archive")
RESULT_DIR = os.getenv("RESULT_DIR", "/app/data/results")


COLUMN_RENAME_MAP = {
    "pkt_size_avg": "Average Packet Size",
    "pkt_len_std": "Packet Length Std",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "flow_duration": "Flow Duration",
    "dst_port": "Destination Port"
}
FEATURE_COLUMNS = [
    "Average Packet Size",
    "Packet Length Std",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Init_Win_bytes_forward",
    "Avg Bwd Segment Size",
    "Flow Duration",
    "Destination Port"
]


# Setup Logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)

sel = selectors.DefaultSelector()
shutdown_event = threading.Event()


# --- Traffic Analysis Worker ---
class TrafficAnalyzer(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True  # Kills thread when main program exits
        self.model = self.load_model("/app/model.pkl")
        logging.info(f"Model type: {type(self.model)}")


    def load_model(self, path):
        logging.info("[ML] Loading model...")
        return joblib.load(path)

    def run(self):
        logging.info("[Analyzer] Worker started. Watching for PCAPs...")
        while not shutdown_event.is_set():
            try:
                self.process_pcaps()
            except Exception as e:
                logging.error(f"[Analyzer] Error in loop: {e}")
            time.sleep(5)  # Check every 5 seconds

    def process_pcaps(self):
        # Find all pcap files
        pcaps = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))

        # We need at least 2 files to be safe:
        # The last one in the list is likely still being written to by tcpdump.
        if len(pcaps) < 2:
            return

        # Process the oldest file
        target_pcap = pcaps[0]
        base_name = os.path.basename(target_pcap)
        # Define specific output CSV path for the Python tool
        output_csv = os.path.join(FLOW_DIR, f"{base_name}.csv")
        archive_csv = os.path.join(FLOW_ARCHIVE_DIR, f"{base_name}.csv")

        logging.info(f"[Analyzer] Extracting flows from {base_name}...")

        try:
            # Python cicflowmeter syntax: cicflowmeter -f <input> -c <output_csv>
            cmd = ["cicflowmeter", "-f", target_pcap, "-c", output_csv]

            # We run this synchronously within the thread
            result =subprocess.run(cmd, check=True, capture_output=True)

            if result.returncode != 0:
                logging.error(f"[Analyzer] CICFlowMeter failed: {result.stderr}")
                return

            if os.path.exists(output_csv):
                self.analyze_flow(output_csv)
                shutil.move(output_csv, archive_csv)  # Archive processed CSV
            else:
                # Sometimes cicflowmeter appends '_Flow.csv' to the name automatically
                autoname = output_csv.replace(".csv", ".pcap_Flow.csv")
                if os.path.exists(autoname):
                    self.analyze_flow(autoname)
                    shutil.move(autoname, archive_csv)
                else:
                    logging.warning(f"[Analyzer] CSV not found at {output_csv}")

        except subprocess.CalledProcessError as e:
            logging.error(f"[Analyzer] CLI Error: {e.stderr.decode()}")
        finally:
            if os.path.exists(target_pcap):
                os.remove(target_pcap)

    def analyze_flow(self, csv_path):
        try:
            result_csv = os.path.join(RESULT_DIR, "result.csv")
            df = pd.read_csv(csv_path)
            if df.empty:
                return
            df = df.rename(columns=COLUMN_RENAME_MAP)
            df = df[FEATURE_COLUMNS]
            preds = self.model.predict(df)
            counter = collections.Counter(preds)

            new_df = pd.DataFrame(counter.items(), columns=["label", "count"])
            if os.path.exists(result_csv):
                old_df = pd.read_csv(result_csv)
                combined = pd.concat([old_df, new_df])
                final_df = combined.groupby("label", as_index=False)["count"].sum()
            else:
                final_df = new_df
            
            final_df.to_csv(result_csv, index=False)
            logging.info(
                f"[ML] Analyzed flows from {os.path.basename(csv_path)}"
            )

        except Exception as e:
            logging.error(f"[Analyzer] CSV processing error: {e}")


# --- Networking Logic (Existing) ---
HEADER_FMT = "!I"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
PAYLOAD_FMT = "!Q f f"
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FMT)


class ConnState:
    __slots__ = ("addr", "recv_buffer", "expected_len")

    def __init__(self, addr):
        self.addr = addr
        self.recv_buffer = b""
        self.expected_len = None


def accept(server_sock):
    try:
        conn, addr = server_sock.accept()
        conn.setblocking(False)
        state = ConnState(addr)
        sel.register(conn, selectors.EVENT_READ, data=state)
        logging.info(f"[+] Connected {addr}")
    except OSError as e:
        logging.error(f"[!] Accept failed: {e}")


def close_conn(conn, state, reason):
    try:
        sel.unregister(conn)
        conn.close()
    except Exception:
        pass
    logging.info(f"[-] Disconnected {state.addr} ({reason})")


def read(conn, state: ConnState):
    try:
        chunk = conn.recv(4096)
    except OSError:
        close_conn(conn, state, "connection error")
        return

    if not chunk:
        close_conn(conn, state, "eof")
        return

    state.recv_buffer += chunk

    while True:
        if state.expected_len is None:
            if len(state.recv_buffer) < HEADER_SIZE:
                return
            try:
                (state.expected_len,) = struct.unpack(
                    HEADER_FMT, state.recv_buffer[:HEADER_SIZE]
                )
                state.recv_buffer = state.recv_buffer[HEADER_SIZE:]
            except struct.error:
                close_conn(conn, state, "bad header")
                return

        if len(state.recv_buffer) < state.expected_len:
            return

        payload = state.recv_buffer[: state.expected_len]
        state.recv_buffer = state.recv_buffer[state.expected_len :]
        state.expected_len = None

        try:
            ts, temp, hum = struct.unpack(PAYLOAD_FMT, payload)
            logging.info(f"[DATA] {state.addr} | T={temp:.2f}°C H={hum:.2f}% ts={ts}")
        except struct.error:
            close_conn(conn, state, "bad payload")
            return


def main():
    signal.signal(signal.SIGTERM, lambda s, f: shutdown_event.set())
    signal.signal(signal.SIGINT, lambda s, f: shutdown_event.set())

    # Start the ML/Analysis thread
    analyzer = TrafficAnalyzer()
    analyzer.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((GATEWAY_IP, GATEWAY_PORT))
        server.listen()
        server.setblocking(False)
        sel.register(server, selectors.EVENT_READ, data=None)

        logging.info(f"[*] Gateway listening on {GATEWAY_IP}:{GATEWAY_PORT}")

        try:
            while not shutdown_event.is_set():
                events = sel.select(timeout=1.0)
                for key, mask in events:
                    if key.data is None:
                        accept(key.fileobj)
                    else:
                        read(key.fileobj, key.data)
        finally:
            logging.info("[*] Shutting down...")
            sel.close()


if __name__ == "__main__":
    main()
