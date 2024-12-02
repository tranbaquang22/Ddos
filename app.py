from flask import Flask, render_template, request
import pandas as pd
import joblib

app = Flask(__name__)

# Load mô hình đã huấn luyện
model = joblib.load("random_forest_model_balanced.pkl")

# Trang chính
@app.route("/")
def index():
    return render_template("index.html")

# Phân tích dữ liệu mạng
@app.route("/analyze", methods=["GET"])
def analyze():
    try:
        # Đọc dữ liệu đã lọc từ file
        data = pd.read_csv("filtered_packets.csv", on_bad_lines="skip")

        # Định nghĩa các cột đặc trưng cần thiết
        required_features = [
            "Time", "Source_IP", "Destination_IP", "duration", "protocol_type", "service", "flag",
            "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
            "num_failed_logins", "logged_in", "num_compromised", "root_shell",
            "su_attempted", "num_root", "num_file_creations", "num_shells",
            "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
            "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
            "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
            "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
            "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ]

        # Đảm bảo rằng các cột cần thiết tồn tại
        for feature in required_features:
            if feature not in data.columns:
                data[feature] = 0  # Gán giá trị mặc định cho các cột thiếu

        # Lọc và giữ lại các cột đặc trưng cần thiết
        data = data[required_features]

        # Đảm bảo cột Time là kiểu thời gian để sắp xếp
        data["Time"] = pd.to_datetime(data["Time"], errors="coerce")

        # Loại bỏ các hàng có giá trị Time không hợp lệ
        data = data.dropna(subset=["Time"])

        # Sắp xếp dữ liệu theo thời gian giảm dần
        data = data.sort_values(by="Time", ascending=False)

        # Phân tích dữ liệu bằng mô hình (bỏ các cột không phải đặc trưng)
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

        # Dự đoán nhãn bằng mô hình
        predictions = model.predict(data[features_for_model])
        data["predicted_label"] = predictions
        data["Status"] = data["predicted_label"].apply(lambda x: "Tấn công" if x == 1 else "Bình thường")

        # Lọc các cảnh báo (những mẫu dự đoán là tấn công)
        warnings = data[data["predicted_label"] == 1]

        # Hiển thị kết quả
        return render_template("results.html", warnings=warnings.to_dict(orient="records"), all_data=data.to_dict(orient="records"))

    except FileNotFoundError:
        return "File filtered_packets.csv không tồn tại. Vui lòng chạy packet_capture.py trước khi phân tích."
    except Exception as e:
        return f"Đã xảy ra lỗi: {e}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
