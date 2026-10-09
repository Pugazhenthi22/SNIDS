import sys, time, csv
from datetime import datetime
from pathlib import Path
import joblib, numpy as np, pandas as pd

ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT/"models"/"balanced_random_forest.joblib"
X_FILE = ROOT/"data"/"processed"/"X_test.parquet"
Y_FILE = ROOT/"data"/"processed"/"y_test.parquet"
LABELS = ROOT/"data"/"processed"/"label_mapping.csv"
OUT = ROOT/"logs"/"replay_alerts.csv"
ATTACK_IDS = [2,3,4,5,6,7,10,11]

n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5

model = joblib.load(MODEL)
X = pd.read_parquet(X_FILE).reset_index(drop=True)
y = pd.read_parquet(Y_FILE)
y = (y["Label_ID"] if "Label_ID" in y.columns else y.iloc[:,0]).astype(int).reset_index(drop=True)
lm = pd.read_csv(LABELS)
names = dict(zip(lm["Label_ID"], lm["Label"]))

rng = np.random.RandomState(42)
per = max(1, (n//2)//len(ATTACK_IDS))
idx = []
for c in ATTACK_IDS:
    pool = np.where(y.values == c)[0]
    if len(pool):
        idx += list(rng.choice(pool, min(per, len(pool)), replace=False))
pool = np.where(y.values == 0)[0]
idx += list(rng.choice(pool, min(n-len(idx), len(pool)), replace=False))
idx = list(rng.permutation(idx))

Xs = X.iloc[idx]
if hasattr(model, "feature_names_in_"):
    Xs = Xs[list(model.feature_names_in_)]
proba = model.predict_proba(Xs)
pred = model.classes_[proba.argmax(axis=1)]

OUT.parent.mkdir(exist_ok=True)
correct = 0
with open(OUT, "a", newline="") as f:
    w = csv.writer(f)
    for k, i in enumerate(idx):
        true = names.get(int(y[i]), str(y[i])); p = names.get(int(pred[k]), str(pred[k]))
        ok = int(y[i]) == int(pred[k]); correct += ok
        pk = int(Xs.iloc[k].get("Total Fwd Packets",0) + Xs.iloc[k].get("Total Backward Packets",0))
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), p, "LOW" if p=="Benign" else "HIGH", "dataset-replay", "CICIDS2017", pk])
        f.flush()
        print(f"{k+1:3d} true={true:<14} pred={p:<14} conf={proba[k].max()*100:5.1f}% {'OK' if ok else 'MISS'}")
        time.sleep(delay)
print(f"\nReplay done: {correct}/{len(idx)} correct ({correct/len(idx)*100:.1f}%)")
print("NOTE: dataset replay, not live traffic.")
