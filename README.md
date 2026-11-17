# Bastion__

Real-time DDoS detection and mitigation using Random Forest, with a live
dashboard for monitoring flagged traffic.

Two coordinated tracks, one shared event contract:

- **Detection** (`detection/`) — traffic generation/capture, feature
  extraction, model training/inference, mitigation (auto-block).
- **Dashboard** (`dashboard/`) — Flask backend + frontend UI consuming
  detection events in real time.

## Repo structure

```
bastion/
├── detection/
│   ├── capture/
│   ├── features/
│   ├── models/
│   └── mitigation/
├── dashboard/
│   ├── backend/
│   ├── frontend/
│   └── data/
├── shared/
│   └── schema.py        # the contract — see below
├── docs/
│   └── PROJECT_PLAN.md
└── README.md
```

## The contract

`shared/schema.py` defines `DetectionEvent` — the only thing the two tracks
need to agree on to build independently. Detection emits it, dashboard
consumes it. Changing this file requires a joint PR both people approve.

```python
detection_event = {
    "timestamp": "ISO8601",
    "src_ip": "string",
    "attack_type": "syn_flood | udp_flood | slowloris | benign",
    "confidence": "float 0-1",
    "action_taken": "blocked | logged | none",
}
```

## Branching

- `main` — always demo-able
- `dev` — integration branch, merge here first
- `feat/<track>-<step>` — e.g. `feat/detection-feature-extraction`,
  `feat/dashboard-flask-skeleton`

Branch off `dev`, PR back into `dev`. Merge `dev` → `main` only at
milestones (viva checkpoints).

## Workflow

- One GitHub Issue per plan step, assigned.
- Open draft PRs early — as soon as you start a step, not when it's done.
- PR review is the sync point, not a standing meeting.
- One-line PR description per merge (what changed, what it outputs) so
  the other person always knows current state.
- Daily 2-line async update in a pinned issue/Discussion: done / blocked / next.

## Plan

See [`docs/PROJECT_PLAN.md`](docs/PROJECT_PLAN.md) for the full 8-week
iterative plan and weekly sync points.
