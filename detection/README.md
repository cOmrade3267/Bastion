# Detection track

Traffic capture → feature extraction → classification → event emission
(and, later, auto-mitigation). Emits `DetectionEvent`s (`shared/schema.py`)
to the dashboard backend.

```
capture/   sniff traffic -> pcap            (VM lab; Scapy, stub)
features/  pcap/synthetic -> feature rows   (FEATURE_COLUMNS = the Week 3 sync contract)
models/    features -> (attack_type, conf)  (rule-based placeholder -> RF in Week 4)
emit/      classification -> DetectionEvent -> POST /event
pipeline.py  end-to-end runner
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

## Status (Week 2)

- ✅ Feature schema (`FEATURE_COLUMNS`), synthetic generator, placeholder
  classifier, emitter, end-to-end pipeline — all runnable.
- 🔸 Real capture (`capture/`) and pcap feature extraction are stubs with
  final interfaces — they fill in once the VM lab is up (#1) and SYN-flood
  traffic is generated/captured (#4).
- 🔸 Classifier is a transparent rule stub; the trained Random Forest
  replaces it behind `classify_row()` in Week 4 (#10).

`shared/schema.py` is the frozen contract — changes go through a joint PR.
