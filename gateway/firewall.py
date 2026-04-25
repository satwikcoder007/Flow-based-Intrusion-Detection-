import subprocess
import threading
import time
import logging


class FirewallManager:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip_temporarily(self, ip, duration=300):
        if ip in self.blocked_ips:
            return

        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

            self.blocked_ips.add(ip)
            logging.warning(f"[BLOCKED] {ip} for {duration}s")

            threading.Thread(
                target=self._unblock_after_delay,
                args=(ip, duration),
                daemon=True
            ).start()

        except Exception as e:
            logging.error(f"[BLOCK ERROR] {e}")

    def _unblock_after_delay(self, ip, delay):
        time.sleep(delay)

        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

            self.blocked_ips.remove(ip)
            logging.info(f"[UNBLOCKED] {ip}")

        except Exception as e:
            logging.error(f"[UNBLOCK ERROR] {e}")