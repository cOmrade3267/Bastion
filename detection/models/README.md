# Detection model (Random Forest)

Issue #10. Classifies a flow into `syn_flood / udp_flood / slowloris / benign`
from the shared `FEATURE_COLUMNS`, behind the stable `classify_row()` interface
that the pipeline and emitter already call.

## Why train on our 9 features, not CICFlowMeter's 80

The model trains on the **same 9 features the live extractor produces**
(`features/extract.py`), so it drops straight into live inference — no
train/serve feature mismatch. CICDDoS2019's rich CSVs are **mapped down** to
those 9 (see `datasets.py`). We deliberately keep **no** socket identifiers
(IP / port / timestamp): the CICDDoS2019 literature shows they leak and produce
fake ~1.0 F1. Preprocessing is sanitation only (Inf/NaN → drop), the split is
stratified, and `class_weight="balanced"` handles the dataset's class imbalance.

## Train

```bash
cd detection && source .venv/bin/activate

# test run — noisy synthetic data, no download needed
python models/train_rf.py --data synthetic --cv

# real data once you have the CSVs
python models/train_rf.py --data cicddos --csv "data/CICDDoS2019/*.csv"
```

Outputs to `detection/models/`:
- `rf_model.joblib` — model + feature order + class list (git-ignored; regenerate)
- `metrics.json` — per-class precision/recall/F1, accuracy, feature importances
- `confusion.csv` — confusion matrix (feeds the dashboard eval notebook, #13/#17)

`classify_row()` auto-loads `rf_model.joblib` if present, else falls back to the
rule-based stub — so the pipeline runs with or without a trained model.

## CICFlowMeter → FEATURE_COLUMNS mapping (`datasets.py`)

| FEATURE_COLUMN | from CICDDoS2019 |
|---|---|
| duration_s | `Flow Duration` / 1e6 |
| pkt_count | `Total Fwd Packets` + `Total Backward Packets` |
| byte_count | `Total Length of Fwd/Bwd Packets` |
| pkts_per_s | `Flow Packets/s` |
| syn_ratio | `SYN Flag Count` / pkt_count |
| udp_ratio | 1 if `Protocol`==17 else 0 |
| unique_dst_ports | 1 (per-flow rows; live extraction provides the real value) |
| mean_iat_ms | `Flow IAT Mean` / 1000 |
| mean_pkt_size | `Average Packet Size` |

Label mapping: `SYN→syn_flood`, `UDP`/`UDP-Lag→udp_flood`,
`Slowloris/Slowhttptest→slowloris`, `BENIGN→benign`. Out-of-schema reflective
attacks (MSSQL, LDAP, NetBIOS, NTP, DNS, SNMP, Portmap) are dropped with a count
— the live detector only knows these four classes. Slowloris is not in
CICDDoS2019; it comes from our own lab/synthetic generation.

## Current baseline (synthetic stand-in)

macro-F1 ≈ **0.98** held-out; 5-fold CV **0.984 ± 0.002**. Top features:
`mean_iat_ms`, `pkts_per_s`, `udp_ratio`, `unique_dst_ports`.

> ⚠️ These numbers are on the **noisy synthetic** dataset, not real CICDDoS2019.
> They exist so the pipeline is testable before the download; real numbers will
> differ (and the synthetic SYN-flood profile uses many dst ports, so a real
> single-port SYN flood currently scores lower confidence until retrained on
> real data). Re-run with `--data cicddos` for the real baseline (#8 sync).
