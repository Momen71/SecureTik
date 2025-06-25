import json
import csv

input_path = "/var/log/suricata/eve.json"
output_path = "labeled_alerts.csv"

with open(input_path, "r") as infile, open(output_path, "w", newline="") as outfile:
    writer = csv.writer(outfile)
    writer.writerow(["pkts_toserver", "pkts_toclient", "sig_len", "proto", "severity", "label"])  # label=1:attack, 0:normal

    for line in infile:
        try:
            data = json.loads(line)
            if "alert" in data and "flow" in data:
                pkts_to_srv = data["flow"].get("pkts_toserver", 0)
                pkts_to_cli = data["flow"].get("pkts_toclient", 0)
                sig_len = len(data["alert"].get("signature", ""))
                proto = data.get("proto", "")
                severity = data["alert"].get("severity", 1)

                # Convert proto to number
                proto_num = {"TCP": 1, "UDP": 2, "ICMP": 3}.get(proto.upper(), 0)

                # TEMPORARY LABEL: treat severity 1 as attack
                label = 1 if severity <= 2 else 0

                writer.writerow([pkts_to_srv, pkts_to_cli, sig_len, proto_num, severity, label])
        except:
            continue

print("[+] CSV file saved:", output_path)
