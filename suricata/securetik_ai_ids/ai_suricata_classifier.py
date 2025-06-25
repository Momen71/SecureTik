import json
from joblib import load
import pandas as pd
import numpy as np

model = load("ai_ids_model.joblib")

feature_columns = ["pkts_toserver", "pkts_toclient", "sig_len", "proto", "severity"]

def extract_features(alert):
    pkts_to_srv = alert.get("flow", {}).get("pkts_toserver", 0)
    pkts_to_cli = alert.get("flow", {}).get("pkts_toclient", 0)
    sig_len = len(alert.get("alert", {}).get("signature", ""))
    proto = {"TCP": 1, "UDP": 2, "ICMP": 3}.get(alert.get("proto", "").upper(), 0)
    severity = alert.get("alert", {}).get("severity", 1)
    return [pkts_to_srv, pkts_to_cli, sig_len, proto, severity]

with open("/var/log/suricata/eve.json", "r") as f:
    for line in f:
        try:
            data = json.loads(line)
            if "alert" in data and "flow" in data:
                features = extract_features(data)
                features_df = pd.DataFrame([features], columns=feature_columns)
                prediction = model.predict(features_df)[0]
                if prediction == 1:
                    print("[🔥 AI DETECTED ATTACK]:", data["alert"]["signature"])
        except:
            continue
