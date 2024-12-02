from scapy.all import sniff, IP, TCP, UDP
from scapy.config import conf
from collections import Counter
from datetime import datetime
import csv
import pandas as pd
import joblib

# Tải mô hình đã huấn luyện
model = joblib.load("random_forest_model_balanced.pkl")

# Định nghĩa các đặc trưng cần thiết cho mô hình
features_for_model = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

# Đếm số lượng gói tin theo IP nguồn
ip_counter = Counter()

# Ngưỡng cảnh báo DDoS (có thể điều chỉnh)
DDOS_THRESHOLD = 1000

# Tạo file CSV để lưu gói tin
with open("filtered_packets.csv", "w", newline="", encoding="utf-8") as csv_file:
    writer = csv.DictWriter(
        csv_file,
        fieldnames=["Time", "Source_IP", "Destination_IP", "Prediction", "Status"] + features_for_model
    )
    writer.writeheader()  # Tiêu đề cột

# Hàm xử lý gói tin
def packet_callback(packet):
    try:
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        packet_length = len(packet)

        # Lấy thông tin giao thức
        protocol_type = 0  # TCP
        if packet.haslayer(TCP):
            protocol_type = 0
        elif packet.haslayer(UDP):
            protocol_type = 1
        else:
            protocol_type = 2  # ICMP hoặc khác

        # Lấy các đặc trưng động
        service = 1 if packet.haslayer(TCP) and packet[TCP].sport == 80 else 0  # Giả định HTTP
        flag = 0 if packet.haslayer(TCP) else 1  # Giả định SF hoặc khác

        # Tạo dữ liệu đầu vào cho mô hình
        row = {
            "duration": 1,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": packet_length,
            "dst_bytes": len(packet[IP].payload) if packet.haslayer(IP) else 0,
            "land": 1 if source_ip == destination_ip else 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1 if source_ip == "127.0.0.1" else 0,  # Giả định nếu là localhost
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

        # Chuyển đổi thành DataFrame để dự đoán
        feature_values_df = pd.DataFrame([row], columns=features_for_model)

        # Dự đoán
        prediction = model.predict(feature_values_df)[0]
        status = "Tấn công" if prediction == 1 else "Bình thường"

        # Ghi dữ liệu vào file CSV
        with open("filtered_packets.csv", "a", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow([
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                source_ip,
                destination_ip,
                prediction,
                status
            ] + list(row.values()))

        # Hiển thị cảnh báo nếu phát hiện tấn công
        if prediction == 1:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{now}] [CẢNH BÁO] Tấn công từ IP: {source_ip}")
            with open("ddos_alerts.log", "a", encoding="utf-8") as log_file:
                log_file.write(f"[{now}] [CẢNH BÁO] Tấn công từ IP: {source_ip}\n")

        # Cập nhật bộ đếm gói tin theo IP
        ip_counter[source_ip] += 1

    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

# Liệt kê các giao diện mạng khả dụng
print("Các giao diện mạng khả dụng:", conf.ifaces)

# Bắt gói tin mạng
print("Đang giám sát mạng...")
try:
    sniff(prn=packet_callback, filter="ip", store=False, count=0)
except KeyboardInterrupt:
    print("\nĐã dừng giám sát mạng.")
