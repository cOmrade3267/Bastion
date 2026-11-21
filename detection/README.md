# Detection track

Traffic capture → feature extraction → classification → event emission
(and, later, auto-mitigation). Emits `DetectionEvent`s (`shared/schema.py`)
to the dashboard backend.

```
capture/   sniff traffic -> pcap            (VM lab; Scapy, stub)
features/  pcap/synthetic -> feature rows   (FEATURE_COLUMNS = the Week 3 sync contract)
models/    features -> (attack_type, conf)  (RF model, rule-based fallback) + benchmark
emit/      classification -> DetectionEvent -> POST /event
mitigate/  detection -> firewall auto-block (nftables/iptables, timeout, LOGGED/BLOCKED)
pipeline.py  end-to-end runner (add --mitigate to auto-block)
```

## Run (no lab needed — synthetic flows)

```bash
cd detection
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python pipeline.py --dry-run                      # print contract-valid events
python pipeline.py --url http://127.0.0.1:5000    # emit to a running dashboard
```

Inspect pieces individually:

```bash
python features/extract.py     # synthetic feature table
python models/classify.py      # placeholder predictions vs. ground truth
```

## Test without the lab

`capture/synth_pcap.py` crafts a small labeled pcap (one source per class) so
the real extractor can be exercised now:

```bash
python capture/synth_pcap.py --out /tmp/bastion_synth.pcap
python pipeline.py --source pcap --path /tmp/bastion_synth.pcap --dry-run
```

## Auto-mitigation (#16)

`--mitigate` turns a detection into a firewall block. It is **safe by default**:
plan mode records the decision and logs the exact command it *would* run, but
touches nothing. Pass `--enforce` (needs root) to actually block.

```bash
# plan mode — see what would be blocked, firewall untouched
python pipeline.py --source synthetic --n 10 --mitigate --dry-run

# real blocking against a running dashboard (root)
sudo python pipeline.py --source pcap --path capture.pcap \
     --url http://127.0.0.1:5000 --mitigate --enforce \
     --threshold 0.8 --block-seconds 300 --allow 10.0.0.1
```

Each attack above the confidence threshold → `action_taken=BLOCKED` (a real rule
with an auto-unblock timeout); below threshold or allowlisted → `LOGGED`; benign
→ `NONE`. Loopback is never blocked. Backend auto-selects nftables → iptables →
log-only. See `mitigate/README.md` for the safety model and the standalone demo
(`python -m mitigate.blocker`).

## Model benchmark (#16)

`models/benchmark.py` compares the RF baseline against ExtraTrees, HistGradient-
Boosting, an MLP, and XGBoost (if installed) on the same split. See
`models/README.md` → *Benchmark*.

## Status

- ✅ Feature schema (`FEATURE_COLUMNS`), synthetic generator, emitter,
  end-to-end pipeline — all runnable.
- ✅ **Real pcap feature extraction** (`extract_from_pcap`) — groups packets by
  source IP and computes `FEATURE_COLUMNS`; verified on a synthetic pcap.
- ✅ **Random Forest classifier** (#10) behind `classify_row()`, with a rule
  fallback when no model is committed.
- ✅ **Auto-block mitigation** (#16) — nftables/iptables with timeout + logging,
  safe plan-mode default; `action_taken` set truthfully.
- ✅ **Model benchmark** (#16) — RF vs alternatives on one split.
- 🔸 Live packet capture (`capture/capture.py`, Scapy sniff) is still a stub —
  it needs the monitor VM + root (#1). `synth_pcap.py` covers dev meanwhile.
- 🔸 Metrics are on the synthetic stand-in until real CICDDoS2019 CSVs are
  loaded (`--data cicddos`); that's the #8 sync.

`shared/schema.py` is the frozen contract — changes go through a joint PR.
