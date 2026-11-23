# Mitigation — auto-block (#16)

Turns a detection into a firewall action, with a safety-first design. One class,
`Blocker`, owns the policy and the firewall state; the pipeline calls exactly one
method per flow.

## The one decision point

```python
action = blocker.consider(attack_type, confidence, src_ip)  # -> ActionTaken
```

`consider` returns the value that goes straight into the `DetectionEvent`, so
`action_taken` is always truthful:

| situation | `action_taken` | firewall |
|---|---|---|
| benign | `NONE` | — |
| attack, confidence ≥ threshold, blockable | `BLOCKED` | rule added (or planned) with a timeout |
| attack, confidence < threshold | `LOGGED` | — |
| attack, IP allowlisted / not an IP | `LOGGED` | — (refused) |
| attack, but `enforce` command failed | `LOGGED` | — (honest downgrade) |
| mitigation disabled | `LOGGED` | — |

## Safety model (why this won't lock you out)

1. **Plan mode is the default.** `enforce=False` records the decision and logs
   the exact command it *would* run (`[PLAN] ...`) but never touches the
   firewall. You opt in to real blocking with `--enforce` (and root). Perfect
   for the live demo without needing root.
2. **Loopback is always allowed** (`127.0.0.1`, `::1`, `0.0.0.0`), plus any
   `--allow` IPs (e.g. your SSH client, the dashboard host). A flagged
   allowlisted IP is `LOGGED`, never blocked.
3. **Every block has a timeout.** A background sweeper auto-unblocks expired IPs
   (`--block-seconds`, default 300). `close()` / the context manager flushes
   every rule the process added — nothing is left behind.
4. **Honest failure.** If an `--enforce` command fails (e.g. not root), the IP is
   reported `LOGGED`, not `BLOCKED` — the event never claims a block that isn't
   there.

## Backends

Auto-selected: **nftables** → **iptables** → **log-only** (`--backend` to force one).

- **nftables** — a self-contained `inet bastion` table with a `blocklist` set and
  one drop rule; per-IP elements are added/removed.
- **iptables** — `-I INPUT -s <ip> -j DROP` / `-D ...`.
- **log-only** — records intent only, never shells out (used when no firewall is
  present, or on purpose). The sweeper is the single source of truth for expiry
  across all three, so behaviour is identical with or without a kernel.

## Try it (no root, nothing touched)

```bash
# standalone demo of the policy + timeout + sweep
python -m mitigate.blocker

# in the pipeline, plan mode
python pipeline.py --source synthetic --n 10 --mitigate --dry-run
```

Real enforcement (root):

```bash
sudo python pipeline.py --source pcap --path capture.pcap \
     --url http://127.0.0.1:5000 --mitigate --enforce \
     --threshold 0.8 --block-seconds 300 --allow 10.0.0.1
```
