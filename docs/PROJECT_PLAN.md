# Bastion — Project Plan

DDoS attack detection (Random Forest) + real-time Flask dashboard, with
auto-mitigation. Two-person split: **Detection** track and **Dashboard** track.

## Week 1 — Setup & contract
- Detection: isolated VM lab (attacker/victim/monitor); verify hping3/Scapy
  can generate and capture traffic between VMs.
- Dashboard: download CICDDoS2019 + SDN dataset; initial EDA (class
  distribution, feature list).
- **Sync:** both PR into `dev`. Jointly merge `shared/schema.py` — unblocks
  everything downstream.

## Week 2 — First working slice
- Detection: generate SYN flood traffic, capture pcap, basic feature
  extractor for that one flow type.
- Dashboard: clean/normalize dataset; Flask skeleton with one dummy endpoint
  accepting `detection_event` JSON matching the schema.
- **Sync:** POST a hand-crafted event to the endpoint, confirm it's
  received/stored correctly.

## Week 3 — Expand coverage
- Detection: add UDP flood + Slowloris generation/extraction — all 3 attack
  types + benign now produce features.
- Dashboard: merge detection's live features with CICDDoS2019 into one
  schema-aligned matrix; start baseline RF training script.
- **Sync:** compare feature schemas column-for-column.

## Week 4 — Model v1 + dashboard skeleton
- Detection: train RF on combined dataset; baseline precision/recall/F1 per
  class.
- Dashboard: real UI (traffic volume, flagged IP list) reading from Flask
  backend, still on mock/replayed events.
- **Sync:** demo checkpoint, merge to `main`. Full walkthrough: traffic →
  features → classification → (mocked) dashboard event.

## Week 5 — Real-time wiring
- Detection: sliding-window live inference loop (capture → extract →
  classify continuously).
- Dashboard: replace mock events with WebSocket/polling from the real
  backend; add confidence + attack-type coloring.
- **Sync:** first real end-to-end test — live attack visible on dashboard
  within seconds.

## Week 6 — Mitigation + benchmarking
- Detection: iptables/nftables auto-block on detection (timeout + logging);
  benchmark XGBoost/LSTM against RF baseline.
- Dashboard: blocked-IP log view; start evaluation notebook (confusion
  matrices, per-class charts).
- **Sync:** confirm `action_taken` populates correctly end-to-end.

## Week 7 — Explainability + polish
- Detection: SHAP explainability, wire top-feature explanation into the
  event (schema extension → re-sync, joint PR).
- Dashboard: finalize evaluation report, architecture diagram, UI polish.
- **Sync:** any schema change → joint PR, same rule as Week 1.

## Week 8 — Integration hardening + demo prep
- Both: full run-through, fix integration bugs, write demo script, rehearse
  viva walkthrough, finalize documentation.

Every Friday sync: open PRs into `dev`, review each other's, confirm the
schema still holds, merge.
