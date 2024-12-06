from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

# Trang chính
@app.route("/")
def index():
    return render_template("index.html")

# Phân tích dữ liệu mạng
@app.route("/analyze", methods=["GET"])
def analyze():
    try:
        # Đọc dữ liệu đã phân tích từ file
        data = pd.read_csv("analyzed_packets.csv", on_bad_lines="skip")

        # Đảm bảo cột Time tồn tại
        if "Time" not in data.columns:
            raise KeyError("Cột 'Time' không tồn tại trong dữ liệu.")

        # Chuyển cột Time thành datetime
        data["Time"] = pd.to_datetime(data["Time"], errors="coerce")
        data = data.dropna(subset=["Time"])
        data = data.sort_values(by="Time", ascending=False)

        # Phân loại theo nhãn
        warnings = data[data["Status"] == "Tấn công"]
        normal = data[data["Status"] == "Bình thường"]

        # Hiển thị kết quả
        return render_template(
            "results.html",
            warnings=warnings.to_dict(orient="records"),
            normal_data=normal.to_dict(orient="records"),
            all_data=data.to_dict(orient="records")
        )
    except FileNotFoundError:
        return "File 'analyzed_packets.csv' không tồn tại. Hãy chạy phân tích trước."
    except Exception as e:
        return f"Đã xảy ra lỗi: {e}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
