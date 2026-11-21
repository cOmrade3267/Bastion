# Bastion — Execution Plan (resource collection → completion)

Concrete, dependency-ordered plan to finish the remaining work. Tracks:
**D** = Detection (Soham), **Dash** = Dashboard (Priyanshu), **Joint** = both.

Any change to `shared/schema.py` is a **joint PR, both approve** (Week-1 rule).

---

## Phase 0 — Close the loose ends (~15 min)

**0a. Land Detection CI [D]** — `.github/workflows/detection-ci.yml` needs the
`workflow` OAuth scope to push, so use one of:
- **Web UI (no scope):** GitHub → **Add file → Create new file** →
  `.github/workflows/detection-ci.yml` → paste the YAML → PR into `dev`.
- **Scope:** `gh auth refresh -h github.com -s workflow` (finish the browser
  step; verify with `gh auth status`), then push the branch.
- **Done when:** a green "Detection CI" check shows on PRs touching `detection/`.

**0b. Merge PR #31 [D]** (CICDDoS2019 official train/test split) after CI green.

**0c. Fix remote casing [D]:**
`git remote set-url origin https://github.com/cOmrade3267/Bastion.git`

---

## Phase 1 — Real dataset + real metrics [D] — VIVA-CRITICAL (~2–4 hrs)

### Resource collection
1. **CICDDoS2019** (syn_flood, udp_flood, benign) —
   https://www.unb.ca/cic/datasets/ddos-2019.html → accept licence → download
   the **CSV** folders `CSV-01-12/` (train day) and `CSV-03-11/` (test day).
   Not the pcaps (20+ GB). Kaggle mirror is the fast fallback.
2. **CIC-IDS2017** (slowloris — NOT in CICDDoS2019) —
   https://www.unb.ca/cic/datasets/ids-2017.html → the `...DoS...` CSVs
   (Wednesday: Slowloris + Slowhttptest).

### Placement (already git-ignored)
```
detection/models/data/CICDDoS2019/CSV-01-12/*.csv
detection/models/data/CICDDoS2019/CSV-03-11/*.csv
detection/models/data/CICIDS2017/*.csv
```

### Verify before training (catch column mismatches early)
```bash
cd detection/models
python -c "from datasets import load_cicddos2019 as L; d=L('data/CICDDoS2019/CSV-01-12/*.csv'); print(d.shape); print(d['label'].value_counts())"
```

### Execute — official train/test protocol (the honest number)
```bash
python train_rf.py --data cicddos \
  --train-csv "data/CICDDoS2019/CSV-01-12/*.csv data/CICIDS2017/*.csv" \
  --test-csv  "data/CICDDoS2019/CSV-03-11/*.csv" --cv
```
- **Done when:** `metrics.json` shows `"protocol": "official train/test day split"`,
  all 4 classes have non-zero support, no "class absent from training" warning.
  Commit `metrics.json` + `confusion.csv` via a PR into `dev`.
- **Gotcha:** a real macro-F1 of ~0.7–0.9 is expected and GOOD (no leakage).
  Do not chase 0.98 — document the honest number.

---

## Phase 2 — Dashboard merge chain [Dash] (parallel with Phase 1, ~1 hr)

Stacked drafts. Merge order **#24 (Flask) → #28 (SQLite) → #27 (UI)**:
1. Mark each **Ready for review** (currently draft).
2. Rebase each onto the new `dev`: `git rebase origin/dev`.
3. Retarget bases to `dev`, resolve conflicts, merge in order.
- **Done when:** `dev` has `dashboard/backend/app.py` + `dashboard/frontend/`
  and `python dashboard/backend/app.py` serves the UI at `127.0.0.1:5000`.

---

## Phase 3 — End-to-end integration (needs Phase 1 model + Phase 2 dashboard, ~30 min)

```bash
# terminal 1
python dashboard/backend/app.py
# terminal 2
python detection/pipeline.py --n 20 --seed 1 --url http://127.0.0.1:5000
```
- **Done when:** events POST `202`, appear in `/events`, and render on the UI.
  Extend CI with a Flask round-trip job (`send_test_event.py`: 202 valid / 400 bad).

---

## Phase 4 — Real-time wiring (Plan W5) [Joint] (~1 day)

- **D:** sliding-window live loop — `capture → extract → classify → emit` on a
  timer; wrap the `pipeline.py` body in a windowed `while`; add
  `--interface` + `--window` flags.
- **Dash:** replace mock events with polling (`GET /events?since=`) or WebSocket;
  colour by `attack_type` + `confidence`.
- **Done when:** a live `hping3` SYN flood in the lab shows on the dashboard
  within seconds.

---

## Phase 5 — SHAP explainability (Plan W7) [Joint — schema change] (~0.5 day)

⚠️ Touches `shared/schema.py` → **joint PR, both approve.**
1. Extend `DetectionEvent` with optional `top_features: list[str]` (optional so
   old events still validate).
2. **D:** compute per-prediction SHAP top-3 in `classify.py`; populate in `emitter.py`.
3. **Dash:** show the "why" on each flagged event.
- **Done when:** a blocked event carries its top-3 driving features end to end.

---

## Phase 6 — Hardening + demo (Plan W8) [Joint] (~1–2 days)

- Full run-through; fix integration bugs; evaluation notebook (confusion matrix
  + per-class charts from the real `metrics.json`).
- Write a **demo script** (exact commands in order); rehearse the viva:
  traffic → capture → features → RF classification → mitigation → live
  dashboard → SHAP explanation.
- Finalize README + architecture diagram.
- **Done when:** the whole story runs cold in <5 min and `main` is tagged `v1.0`.

---

## Critical path

```
Phase 0 ─┐
         ├─ Phase 1 (real metrics) ─┐
Phase 2 ─┘ (dashboard merge) ───────┴─ Phase 3 ─ Phase 4 ─ Phase 5 ─ Phase 6
```

**The two true blockers are external:** (1) downloading the datasets,
(2) the `workflow` scope / web-UI step for CI. Everything else is unblocked.
