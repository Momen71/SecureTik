import json
import pandas as pd
from joblib import load
from datetime import datetime

input_path = "/var/log/suricata/eve.json"
output_path = "ai_alerts.json"

model = load("ai_ids_model.joblib")
feature_columns = ["pkts_toserver", "pkts_toclient", "sig_len", "proto", "severity"]

def extract_features(data):
    pkts_to_srv = data.get("flow", {}).get("pkts_toserver", 0)
    pkts_to_cli = data.get("flow", {}).get("pkts_toclient", 0)
    sig_len = len(data.get("alert", {}).get("signature", ""))
    proto = {"TCP": 1, "UDP": 2, "ICMP": 3}.get(data.get("proto", "").upper(), 0)
    severity = data.get("alert", {}).get("severity", 1)
    return [pkts_to_srv, pkts_to_cli, sig_len, proto, severity]

def build_alert_record(data, prediction, confidence):
    return {
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
        "src_ip": data.get("src_ip", ""),
        "dest_ip": data.get("dest_ip", ""),
        "proto": data.get("proto", ""),
        "signature": data.get("alert", {}).get("signature", ""),
        "severity": data.get("alert", {}).get("severity", 1),
        "ai_confidence": round(confidence, 2),
        "prediction": int(prediction)
    }

alerts = []

with open(input_path, "r") as infile:
    for line in infile:
        try:
            data = json.loads(line)
            if "alert" in data and "flow" in data:
                features = extract_features(data)
                df = pd.DataFrame([features], columns=feature_columns)

                prediction = model.predict(df)[0]
                confidence = model.predict_proba(df)[0][1]  # probability of being attack (class 1)

                if prediction == 1:
                    alerts.append(build_alert_record(data, prediction, confidence))
        except Exception as e:
            continue

# Save to JSON
with open(output_path, "w") as f:
    json.dump(alerts, f, indent=2)

print(f"[+] AI alerts saved to {output_path} ({len(alerts)} entries)")
