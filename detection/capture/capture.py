"""
Bastion — traffic capture (stub)
================================
Sniffs packets on the monitor VM and writes a pcap for feature extraction.

STUB: the interface is here; the body fills in once the VM lab exists (#1).
Sniffing needs Scapy and root/CAP_NET_RAW, so this is not run in CI or on a
dev laptop — the synthetic path in features/extract.py covers development.
"""

from __future__ import annotations


def capture_to_pcap(iface: str, out_path: str, seconds: int = 30) -> str:
    """Capture `seconds` of traffic on `iface`, write to `out_path`, return it.

    STUB — implement on the monitor VM:
        from scapy.all import sniff, wrpcap
        pkts = sniff(iface=iface, timeout=seconds)
        wrpcap(out_path, pkts)
        return out_path
    """
    try:
        from scapy.all import sniff, wrpcap  # noqa: F401
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "Scapy is required for capture. Install on the monitor VM: "
            "`pip install scapy`. See detection/capture/README.md."
        ) from e
    raise NotImplementedError(
        "capture_to_pcap is a Week 2 lab task (#1/#4). Run on the monitor VM "
        "with root. Until the lab is up, use synthetic flows for development."
    )
