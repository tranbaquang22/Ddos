import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
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

# Cân bằng dữ liệu
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

# Chia tập dữ liệu
X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42)

# Huấn luyện mô hình
model = RandomForestClassifier(n_estimators=10, class_weight="balanced", random_state=42)
model.fit(X_train, y_train)

# Đánh giá mô hình
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, zero_division=1))

# Lưu mô hình
joblib.dump(model, "random_forest_model_balanced.pkl")
