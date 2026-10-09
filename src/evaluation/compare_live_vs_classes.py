import pandas as pd

X = pd.read_parquet("data/processed/X_test.parquet")
y = pd.read_parquet("data/processed/y_test.parquet")["Label_ID"]

live = {
    "Flow Duration": 401.5,
    "Total Fwd Packets": 32,
    "Total Backward Packets": 28,
    "Fwd Packets Length Total": 3004,
    "Bwd Packets Length Total": 1864,
    "Fwd Packet Length Max": 98,
    "Bwd Packet Length Max": 74,
    "Flow Bytes/s": 12124627,
    "Flow Packets/s": 149440,
    "Flow IAT Mean": 6.8,
    "PSH Flag Count": 28,
    "SYN Flag Count": 4,
    "ACK Flag Count": 58,
    "Init Fwd Win Bytes": 65495,
    "Init Bwd Win Bytes": 65483,
}

cols = list(live)
table = {"LIVE flood": pd.Series(live)}
for name, lid in [("Benign", 0), ("DDoS", 2), ("DoS Hulk", 4)]:
    table[name + " (median)"] = X[y == lid][cols].median()

pd.set_option("display.float_format", lambda v: f"{v:,.1f}")
pd.set_option("display.width", 200)
print(pd.DataFrame(table))
