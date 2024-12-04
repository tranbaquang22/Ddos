import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Đọc dữ liệu KDD Cup 99
columns = [
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
    "dst_host_srv_rerror_rate", "label"
]

# Đọc tập dữ liệu
data = pd.read_csv("kddcup.data_10_percent_corrected", names=columns)

# Gộp các nhãn tấn công thành nhãn "attack"
data["label"] = data["label"].apply(lambda x: "attack" if x != "normal." else "normal")

# Mã hóa nhãn
data["label"] = data["label"].astype("category").cat.codes

# Chuyển các cột phân loại thành số
for column in ["protocol_type", "service", "flag"]:
    data[column] = data[column].astype("category").cat.codes

# Tách dữ liệu
X = data.drop(columns=["label"])
y = data["label"]

# Tính ngưỡng cho các đặc trưng quan trọng
important_features = ["count", "src_bytes", "dst_bytes", "duration"]
thresholds = {}

# Tách dữ liệu thành attack và normal
attack_data = data[data["label"] == 1]
normal_data = data[data["label"] == 0]

for feature in important_features:
    thresholds[feature] = {
        "attack_mean": attack_data[feature].mean(),
        "attack_std": attack_data[feature].std(),
        "normal_mean": normal_data[feature].mean(),
        "normal_std": normal_data[feature].std(),
        "attack_75th_percentile": attack_data[feature].quantile(0.75),
        "normal_75th_percentile": normal_data[feature].quantile(0.75)
    }

print("Ngưỡng tính toán từ dữ liệu:")
for feature, stats in thresholds.items():
    print(f"{feature}: {stats}")

# Chia tập dữ liệu (KHÔNG sử dụng SMOTE)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Huấn luyện mô hình
model = RandomForestClassifier(n_estimators=100, max_depth=None, class_weight="balanced", random_state=42)
model.fit(X_train, y_train)

# Đánh giá mô hình
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, zero_division=1))

# Lưu mô hình
joblib.dump(model, "random_forest_model_balanced.pkl")

# Kiểm tra tỷ lệ giữa các nhãn
print("Tỷ lệ nhãn trước khi huấn luyện:")
print(y.value_counts())
