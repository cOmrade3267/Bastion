# Detection model (Random Forest)

Issue #10. Classifies a flow into the **InSDN taxonomy**
`benign / dos / ddos / probe` (see `shared/schema.py` `AttackType`) from the
shared `FEATURE_COLUMNS`, behind the stable `classify_row()` interface that the
pipeline and emitter already call.

> The project trains on **InSDN** (SDN-specific dataset), not CICDDoS2019 — the
> pivot in #35. The CICDDoS loader (`datasets.load_cicddos2019`) is kept for
> reference only; it maps to the retired `{syn_flood,udp_flood,slowloris}`
> taxonomy and is **not** contract-compatible.

## Why train on our 9 features, not CICFlowMeter's 80

The model trains on the **same 9 features the live extractor produces**
(`features/extract.py`), so it drops straight into live inference — no
train/serve feature mismatch. InSDN's CICFlowMeter CSVs (84 cols) are **mapped
down** to those 9 (see `datasets.py`). We deliberately keep **no** socket
identifiers (IP / port / timestamp): the DDoS literature shows they leak and
produce fake ~1.0 F1. Preprocessing is sanitation only (Inf/NaN → drop), the
split is stratified, and `class_weight="balanced"` handles the heavy class
imbalance (ddos is ~1 % of rows).

## Train

```bash
cd detection && source .venv/bin/activate

# test run — noisy synthetic data, no download needed
python models/train_rf.py --data synthetic --cv

# real data — InSDN (the committed model), from dataset/ at repo root
python models/train_rf.py --data insdn --csv "../../dataset/*.csv" --cv
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

Both InSDN and CICDDoS2019 are CICFlowMeter output, so they share the table
above; only the label taxonomy differs (`datasets.py`):

- **InSDN (live — `load_insdn`):** `Normal→benign`, `DDoS→ddos`, `DoS→dos`,
  `Probe→probe`. Small non-DDoS classes (BFA, Web-Attack, BOTNET, U2R) are
  dropped with a count — the live detector only knows these four.
- **CICDDoS2019 (retired — `load_cicddos2019`, reference only):** `SYN→syn_flood`,
  `UDP/UDP-Lag→udp_flood`, `Slowloris/Slowhttptest→slowloris`, `BENIGN→benign`;
  reflective attacks (MSSQL, LDAP, NetBIOS, NTP, DNS, SNMP, Portmap) dropped.
  Not contract-compatible after the InSDN pivot.

## Real baseline — InSDN (the committed model)

Trained on **152,714** InSDN flows (`dataset/*.csv`), evaluated on a 25 %
held-out test set (38,179 rows). These are the numbers in `metrics.json`.

| class  | precision | recall | F1   | support |
|--------|-----------|--------|------|---------|
| benign | 0.98      | 0.93   | 0.96 | 14,923  |
| dos    | 0.96      | 0.98   | 0.97 | 10,109  |
| probe  | 0.97      | 0.98   | 0.97 | 12,767  |
| ddos   | 0.50      | 0.90   | 0.64 |    380  |

- **accuracy 0.961 · macro-F1 0.885**
- **5-fold CV macro-F1 0.889 ± 0.004** (on the training set)
- Top features: `byte_count` (0.24), `pkt_count` (0.19), `mean_pkt_size` (0.16),
  `syn_ratio` (0.13), `duration_s` (0.11).

### Evaluation protocol & honesty (viva-relevant)

- **Split:** random *stratified* split, seed 42, on **exact-deduplicated** flows
  (`load_insdn` drops duplicate feature+label rows). InSDN ships no official
  train/test *day* split (unlike CICDDoS2019), so there is no temporal protocol
  to use; this is the honest limitation.
- **Is the number leakage-inflated? Evidence says no:**
  1. the 5-fold CV mean (0.889) matches the held-out macro-F1 (0.885) with a
     tiny std (±0.004) — the model generalises across folds, not to one lucky
     split;
  2. `ddos` collapses to ~1,520 unique fingerprints after dedup and scores only
     **0.64 F1** — a leaking model would *memorise* these and score high, not
     low. The hard class staying hard is the tell that we are not overfitting
     near-duplicates.
- **Remaining caveat:** without a flow-grouping key (we deliberately drop
  IP/port/timestamp to avoid socket-identifier leakage) we cannot *fully*
  exclude near-duplicate flood flows straddling the split. The two checks above
  bound that risk; a lab capture with a time-based split (Phase 4) is the next
  step to close it entirely.
- **Do not chase 0.98.** A real macro-F1 of ~0.88 with an honest protocol beats
  a leaked ~1.0.

## Benchmark — RF vs alternatives (#16)

`benchmark.py` trains the RF baseline and alternatives on the **same split** and
the same 9 `FEATURE_COLUMNS`, reporting macro-F1, accuracy, train time, inference
latency (µs/flow) and model size, then ranks them vs RF.

```bash
python models/benchmark.py                        # synthetic
python models/benchmark.py --data cicddos --csv "data/CICDDoS2019/*.csv"
```

Candidates: `random_forest`, `extra_trees`, `hist_gradient_boost`, `mlp`, and
`xgboost` *(only if installed — `pip install xgboost`; it's commented in
`requirements.txt`)*. Results are written to `benchmark.json`.

Representative synthetic run (`--n-per-class 1500`): RF, ExtraTrees and
HistGradientBoosting all land within **±0.001 macro-F1** of each other (~0.980);
the MLP trails slightly. **Verdict: keep RF** — within noise of the best, it is
the simplest model, already wired into `classify_row()`, and needs no extra
dependency.

> The `benchmark.json` figures are on **synthetic** data (model comparison only).
> The real headline is the **InSDN** table above (macro-F1 0.885). Re-run
> `benchmark.py --data insdn --csv "../../dataset/*.csv"` to compare models on
> real data, where a gradient-boosted model may separate `ddos` better.

**On LSTM** (the issue says "XGBoost/LSTM"): an LSTM models an *ordered packet
sequence*, but our features are one aggregated vector per flow — no time axis for
an LSTM to use. We benchmark a small MLP as the neural-net comparison and treat a
true LSTM as a **different feature pipeline** (raw packet sequences) = future
work, not a drop-in swap at this layer.
