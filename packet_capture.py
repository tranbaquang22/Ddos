from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
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

# Biến để lưu gói tin đã thu thập
packet_groups = defaultdict(list)

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

        # Gộp các gói tin trùng lặp dựa trên IP nguồn và đích
        packet_groups[(source_ip, destination_ip)].append({
            "protocol_type": protocol_type,
            "src_bytes": packet_length,
            "dst_bytes": len(packet[IP].payload) if packet.haslayer(IP) else 0
        })

    except Exception as e:
        print(f"Đã xảy ra lỗi trong callback: {e}")

# Phân tích dữ liệu
def analyze_packets():
    try:
        # Tạo DataFrame từ các gói tin đã thu thập
        rows = []
        for (source_ip, destination_ip), packets in packet_groups.items():
            count = len(packets)
            src_bytes = sum(pkt["src_bytes"] for pkt in packets)
            dst_bytes = sum(pkt["dst_bytes"] for pkt in packets)

            row_data = {
                "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "Source_IP": source_ip,
                "Destination_IP": destination_ip,
                "count": count,
                "src_bytes": src_bytes,
                "dst_bytes": dst_bytes
            }

            # Bổ sung các đặc trưng còn thiếu để phù hợp với mô hình
            for feature in features_for_model:
                if feature not in row_data:
                    row_data[feature] = 0  # Giá trị mặc định nếu không có thông tin

            rows.append(row_data)

        # Chuyển đổi thành DataFrame
        df = pd.DataFrame(rows)

        # Lưu DataFrame vào file CSV (raw data)
        df.to_csv("aggregated_packets.csv", index=False)

        # Sử dụng mô hình để phân tích
        if not df.empty:
            df["Prediction"] = model.predict(df[features_for_model])
            df["Status"] = df["Prediction"].apply(lambda x: "Tấn công" if x == 0 else "Bình thường")
        else:
            print("Không có gói tin để phân tích.")

        # Lưu kết quả phân tích vào file CSV
        df.to_csv("analyzed_packets.csv", index=False)
        print("Phân tích hoàn tất. Kết quả lưu trong 'analyzed_packets.csv'.")

    except Exception as e:
        print(f"Đã xảy ra lỗi trong khi phân tích gói tin: {e}")

# Bắt gói tin mạng
print("Đang giám sát mạng... Nhấn Ctrl+C để dừng.")
try:
    sniff(prn=packet_callback, filter="ip", store=False, timeout=60)  # Thu thập trong 60 giây
    print("Thu thập gói tin hoàn tất. Đang phân tích...")
    analyze_packets()
except KeyboardInterrupt:
    print("\nĐã dừng giám sát mạng.")
    print("Đang phân tích...")
    analyze_packets()
