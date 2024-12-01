from scapy.all import sniff, IP
from scapy.config import conf
from collections import Counter
from datetime import datetime
import csv
# Đếm số lượng gói tin theo IP nguồn
ip_counter = Counter()

# Ngưỡng để cảnh báo DDoS
DDOS_THRESHOLD = 1000

# Định nghĩa các cột cho file CSV
features = [
    "Time", "Source_IP", "Destination_IP", "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

# Tạo ánh xạ cho protocol_type, service, và flag
protocol_mapping = {"tcp": 0, "udp": 1, "icmp": 2}
service_mapping = {"http": 0, "ftp": 1, "smtp": 2, "domain_u": 3, "other": 4}
flag_mapping = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTR": 4, "SH": 5, "OTH": 6}

# Tạo file CSV để lưu gói tin
with open("filtered_packets.csv", "w", newline="", encoding="utf-8") as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=features)
    writer.writeheader()  # Tiêu đề cột

# Hàm xử lý gói tin
def packet_callback(packet):
    try:
        # Kiểm tra nếu gói tin không hợp lệ
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        packet_length = len(packet)
        protocol = ip_layer.proto  # Lấy thông tin giao thức

        # Chuyển đổi giá trị chuỗi thành số
        protocol_type = protocol_mapping.get(protocol, protocol_mapping["tcp"])  # Mặc định "tcp"
        service = service_mapping.get("http", service_mapping["other"])          # Mặc định "http"
        flag = flag_mapping.get("SF", flag_mapping["SF"])                        # Mặc định "SF"

        # Tạo dữ liệu mẫu với các giá trị đã mã hóa
        row = {
            "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "Source_IP": source_ip,
            "Destination_IP": destination_ip,
            "duration": 1,  # Mặc định giá trị duration là 1
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": packet_length,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 1,
            "srv_count": 1,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 1,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }

        # Ghi dữ liệu vào file CSV
        with open("filtered_packets.csv", "a", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=features)
            writer.writerow(row)

        # Đếm số lượng gói tin theo IP
        ip_counter[source_ip] += 1

        # Kiểm tra ngưỡng cảnh báo
        if ip_counter[source_ip] > DDOS_THRESHOLD:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{now}] [CẢNH BÁO] DDoS từ IP: {source_ip} với {ip_counter[source_ip]} gói tin!")
            # Ghi log cảnh báo vào file
            with open("ddos_alerts.log", "a", encoding="utf-8") as log_file:
                log_file.write(f"[{now}] [CẢNH BÁO] DDoS từ IP: {source_ip} với {ip_counter[source_ip]} gói tin!\n")
    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

# Liệt kê các giao diện mạng khả dụng
print("Các giao diện mạng khả dụng:", conf.ifaces)

# Bắt gói tin mạng trên giao diện cụ thể
print("Đang giám sát mạng...")
try:
    sniff(prn=packet_callback, filter="ip", store=False, count=0)
except KeyboardInterrupt:
    print("\nĐã dừng giám sát mạng.")
