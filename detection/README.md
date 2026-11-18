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

## Test without the lab

`capture/synth_pcap.py` crafts a small labeled pcap (one source per class) so
the real extractor can be exercised now:

```bash
python capture/synth_pcap.py --out /tmp/bastion_synth.pcap
python pipeline.py --source pcap --path /tmp/bastion_synth.pcap --dry-run
```

## Status (Week 2)

- ✅ Feature schema (`FEATURE_COLUMNS`), synthetic generator, placeholder
  classifier, emitter, end-to-end pipeline — all runnable.
- ✅ **Real pcap feature extraction** (`extract_from_pcap`) — groups packets by
  source IP and computes `FEATURE_COLUMNS` from live captures; verified on a
  synthetic pcap (all four classes extracted + classified correctly).
- 🔸 Live packet capture (`capture/capture.py`, Scapy sniff) is still a stub —
  it needs the monitor VM + root (#1). `synth_pcap.py` covers dev meanwhile.
- 🔸 Classifier is a transparent rule stub; the trained Random Forest
  replaces it behind `classify_row()` in Week 4 (#10).

`shared/schema.py` is the frozen contract — changes go through a joint PR.
