from scapy.all import sniff, IP, TCP, UDP
from scapy.config import conf
from collections import defaultdict
from datetime import datetime, timedelta
import pandas as pd
import joblib
import csv

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

# Ngưỡng được tính toán từ dữ liệu huấn luyện
thresholds = {
    "count": {"attack_mean": 8.16, "attack_std": 17.71, "normal_mean": 411.76, "normal_std": 156.27},
    "src_bytes": {"attack_mean": 1157.05, "attack_std": 34226.12, "normal_mean": 3483.77, "normal_std": 1102603.83},
    "dst_bytes": {"attack_mean": 3384.65, "attack_std": 37578.20, "normal_mean": 251.60, "normal_std": 31798.32},
    "duration": {"attack_mean": 216.66, "attack_std": 1359.21, "normal_mean": 6.62, "normal_std": 402.56}
}

# Biến để nhóm gói tin
packet_groups = defaultdict(list)

# Thời gian hiện tại để nhóm gói tin
current_window_start = datetime.now()

# Tạo file CSV để lưu gói tin
with open("filtered_packets.csv", "w", newline="", encoding="utf-8") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow([
        "Time", "Source_IP", "Destination_IP", "count", "src_bytes", "dst_bytes",
        "Prediction", "Status"
    ] + features_for_model)  # Tiêu đề cột

# Hàm xử lý gói tin
def packet_callback(packet):
    global current_window_start

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

        # Tính toán nhóm gói tin
        now = datetime.now()
        if (now - current_window_start) > timedelta(seconds=15):  # Sau 15 giây, phân tích
            analyze_packets()
            current_window_start = now

        # Thêm gói tin vào nhóm
        packet_groups[(source_ip, destination_ip)].append({
            "protocol_type": protocol_type,
            "src_bytes": packet_length,
            "dst_bytes": len(packet[IP].payload) if packet.haslayer(IP) else 0
        })

    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

# Hàm phân tích các nhóm gói tin
def analyze_packets():
    global packet_groups

    try:
        # Tạo DataFrame để phân tích
        rows = []
        for (source_ip, destination_ip), packets in packet_groups.items():
            count = len(packets)
            src_bytes = sum(pkt["src_bytes"] for pkt in packets)
            dst_bytes = sum(pkt["dst_bytes"] for pkt in packets)

            # Sử dụng ngưỡng để phân loại trước
            if count > thresholds["count"]["normal_mean"] or \
               src_bytes > thresholds["src_bytes"]["normal_mean"] or \
               dst_bytes > thresholds["dst_bytes"]["normal_mean"]:
                prediction = 1  # Gắn nhãn "Tấn công" nếu vượt ngưỡng
            else:
                prediction = 0  # Gắn nhãn "Bình thường"

            rows.append({
                "Source_IP": source_ip,
                "Destination_IP": destination_ip,
                "count": count,
                "src_bytes": src_bytes,
                "dst_bytes": dst_bytes,
                "Prediction": prediction
            })

        # Chuyển đổi thành DataFrame
        df = pd.DataFrame(rows)

        # Bổ sung các cột còn thiếu
        for feature in features_for_model:
            if feature not in df.columns:
                df[feature] = 0

        # Ghi vào CSV
        with open("filtered_packets.csv", "a", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            for _, row in df.iterrows():
                writer.writerow([datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                 row["Source_IP"], row["Destination_IP"],
                                 row["count"], row["src_bytes"], row["dst_bytes"],
                                 row["Prediction"], 
                                 "Tấn công" if row["Prediction"] == 1 else "Bình thường"
                ] + list(row[features_for_model]))

    except Exception as e:
        print(f"Đã xảy ra lỗi trong khi phân tích gói tin: {e}")

    # Reset nhóm gói tin
    packet_groups.clear()

# Bắt gói tin mạng
print("Đang giám sát mạng...")
try:
    sniff(prn=packet_callback, filter="ip", store=False, count=0)
except KeyboardInterrupt:
    print("\nĐã dừng giám sát mạng.")
