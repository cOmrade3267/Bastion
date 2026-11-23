# Capture — VM lab notes

Isolated 3-VM lab (issue #1). All on a host-only / internal network, **no
bridge to the real network** — this generates attack traffic.

```
attacker  ──►  victim
                 ▲
                 │ (mirrored / same segment)
              monitor  ── captures ──► pcap ──► features/extract.py
```

## Generate traffic (attacker VM)

```bash
# SYN flood (Week 2 target)
sudo hping3 -S --flood -p 80 <victim-ip>

# UDP flood (Week 3)
sudo hping3 --udp --flood -p 53 <victim-ip>

# Slowloris (Week 3) — use a slowloris tool against an HTTP server on victim
```

## Capture (monitor VM)

```bash
sudo python capture.py            # once capture_to_pcap() is implemented
# or, by hand:
sudo tcpdump -i <iface> -w syn_flood.pcap
```

Then extract features:

```bash
python ../pipeline.py --source pcap syn_flood.pcap --dry-run
```

## Safety

Keep the lab isolated. `.gitignore` excludes `*.pcap` so captures are not
committed — share sample captures out-of-band.
