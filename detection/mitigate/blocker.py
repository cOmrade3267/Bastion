"""
Bastion — auto-block mitigation (Week 6, #16)
=============================================
Turns a detection into a firewall action, safely.

Design goals, in order:
  1. **Never lock the operator out by accident.** Blocking the real firewall
     is OPT-IN (`enforce=True`); the default is a *plan* mode that records the
     decision and logs the exact command it WOULD run, touching nothing.
  2. **Auto-unblock.** Every block carries a timeout; a background sweeper
     removes expired rules. Closing the Blocker flushes everything it added.
  3. **One decision point.** `consider(attack_type, confidence, src_ip)` is the
     only thing the pipeline calls. It returns the `ActionTaken` that goes
     straight into the DetectionEvent, so `action_taken` is always truthful:
        - BLOCKED  -> a rule is (or would be) in place for this IP
        - LOGGED   -> detected, but policy chose not to block
        - NONE     -> benign

Backends: nftables (preferred) -> iptables -> log-only. The sweeper is the
single source of truth for expiry across all backends, so behaviour is
identical whether or not the kernel is actually involved.

Standalone demo (no root needed, nothing touched):
    python -m mitigate.blocker
"""

from __future__ import annotations

import ipaddress
import logging
import pathlib
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.schema import AttackType, ActionTaken  # noqa: E402

log = logging.getLogger("bastion.mitigate")

# Never block these, even if a model flags them — self-lockout guard.
_ALWAYS_ALLOW = {"127.0.0.1", "::1", "0.0.0.0"}


# --------------------------------------------------------------------------- #
# Firewall backends
# --------------------------------------------------------------------------- #
class Backend:
    """A firewall backend builds the add/remove commands and reports itself."""

    name = "base"
    executes = True  # False => commands are illustrative, never shelled out

    def available(self) -> bool:  # pragma: no cover - trivial
        return False

    def setup_cmds(self) -> list[list[str]]:
        return []

    def add_cmd(self, ip: str) -> list[str]:
        raise NotImplementedError

    def remove_cmd(self, ip: str) -> list[str]:
        raise NotImplementedError


class IptablesBackend(Backend):
    name = "iptables"

    def available(self) -> bool:
        from shutil import which
        return which("iptables") is not None

    def add_cmd(self, ip: str) -> list[str]:
        return ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]

    def remove_cmd(self, ip: str) -> list[str]:
        return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]


class NftablesBackend(Backend):
    """Self-contained `inet bastion` table with a `blocklist` set.

    The set drives a single drop rule; we add/remove set elements per IP.
    Expiry is handled by the Blocker's sweeper (not kernel timeouts) so all
    backends behave the same.
    """

    name = "nftables"
    TABLE = "bastion"

    def available(self) -> bool:
        from shutil import which
        return which("nft") is not None

    def setup_cmds(self) -> list[list[str]]:
        t = self.TABLE
        return [
            ["nft", "add", "table", "inet", t],
            ["nft", "add", "set", "inet", t, "blocklist", "{ type ipv4_addr; }"],
            ["nft", "add", "chain", "inet", t, "input",
             "{ type filter hook input priority -5; policy accept; }"],
            ["nft", "add", "rule", "inet", t, "input", "ip", "saddr", "@blocklist", "drop"],
        ]

    def add_cmd(self, ip: str) -> list[str]:
        return ["nft", "add", "element", "inet", self.TABLE, "blocklist", "{ %s }" % ip]

    def remove_cmd(self, ip: str) -> list[str]:
        return ["nft", "delete", "element", "inet", self.TABLE, "blocklist", "{ %s }" % ip]


class LogOnlyBackend(Backend):
    """No firewall available (or not wanted): record intent only."""

    name = "log-only"
    executes = False

    def available(self) -> bool:
        return True

    def add_cmd(self, ip: str) -> list[str]:
        return ["#", "block", ip]

    def remove_cmd(self, ip: str) -> list[str]:
        return ["#", "unblock", ip]


def pick_backend(prefer: str = "auto") -> Backend:
    """Choose a backend. `prefer` in {auto, nftables, iptables, log-only}."""
    candidates = {
        "nftables": NftablesBackend(),
        "iptables": IptablesBackend(),
        "log-only": LogOnlyBackend(),
    }
    if prefer != "auto":
        b = candidates.get(prefer)
        if b is None:
            raise ValueError(f"unknown backend {prefer!r}")
        return b
    for key in ("nftables", "iptables"):
        if candidates[key].available():
            return candidates[key]
    return candidates["log-only"]


# --------------------------------------------------------------------------- #
# The Blocker
# --------------------------------------------------------------------------- #
@dataclass
class _Entry:
    expires_at: float
    reason: str


class Blocker:
    """Policy + firewall state for auto-mitigation.

    Parameters
    ----------
    enabled : bool
        If False, mitigation is off — attacks are LOGGED, nothing is blocked.
    enforce : bool
        If False (default), run in **plan** mode: decisions are recorded and
        the command that WOULD run is logged, but the firewall is untouched.
        Set True to actually execute firewall commands.
    threshold : float
        Minimum confidence to block. Below it, an attack is LOGGED, not blocked.
    block_seconds : int
        Auto-unblock timeout per IP.
    allow : iterable[str]
        Extra IPs never to block (loopback is always allowed).
    backend : str
        "auto" | "nftables" | "iptables" | "log-only".
    sweep : bool
        Start a background thread that auto-unblocks expired IPs. Off by default
        so short scripts stay deterministic; the pipeline turns it on.
    """

    def __init__(self, *, enabled: bool = True, enforce: bool = False,
                 threshold: float = 0.8, block_seconds: int = 300,
                 allow: "list[str] | None" = None, backend: str = "auto",
                 sweep: bool = False):
        self.enabled = enabled
        self.enforce = enforce
        self.threshold = float(threshold)
        self.block_seconds = int(block_seconds)
        self.allow = set(_ALWAYS_ALLOW) | set(allow or [])
        self.backend = pick_backend(backend)
        self._blocked: "dict[str, _Entry]" = {}
        self._lock = threading.Lock()
        self._setup_done = False
        self._sweeper: "threading.Thread | None" = None
        self._stop = threading.Event()
        if enabled and enforce:
            self._ensure_setup()
        if sweep:
            self._start_sweeper()

    # -- policy -------------------------------------------------------------- #
    def consider(self, attack_type: AttackType, confidence: float, src_ip: str) -> ActionTaken:
        """The one call the pipeline makes. Returns the truthful ActionTaken."""
        if attack_type == AttackType.BENIGN:
            return ActionTaken.NONE
        if not self.enabled:
            return ActionTaken.LOGGED
        if confidence < self.threshold:
            log.info("detect %s from %s conf=%.2f < %.2f -> LOGGED (below threshold)",
                     attack_type.value, src_ip, confidence, self.threshold)
            return ActionTaken.LOGGED
        if not self._blockable(src_ip):
            log.warning("detect %s from %s -> LOGGED (allowlisted/invalid, not blocking)",
                        attack_type.value, src_ip)
            return ActionTaken.LOGGED
        ok = self.block(src_ip, reason=f"{attack_type.value} conf={confidence:.2f}")
        return ActionTaken.BLOCKED if ok else ActionTaken.LOGGED

    # -- block / unblock ----------------------------------------------------- #
    def block(self, ip: str, reason: str = "manual") -> bool:
        """Add (or refresh) a block for `ip`. Returns True if blocked/planned."""
        if not self._blockable(ip):
            return False
        with self._lock:
            expires = time.monotonic() + self.block_seconds
            if ip in self._blocked:
                self._blocked[ip].expires_at = expires  # extend, rule already in place
                log.info("refresh block %s (%s) +%ds", ip, reason, self.block_seconds)
                return True
            ok = self._run(self.backend.add_cmd(ip), verb="block", ip=ip)
            if ok:
                self._blocked[ip] = _Entry(expires_at=expires, reason=reason)
                log.info("BLOCK %s (%s) for %ds via %s%s", ip, reason, self.block_seconds,
                         self.backend.name, "" if self.enforce else " [PLAN]")
            return ok

    def unblock(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._blocked:
                return False
            ok = self._run(self.backend.remove_cmd(ip), verb="unblock", ip=ip)
            self._blocked.pop(ip, None)  # drop state regardless, to avoid leaks
            log.info("UNBLOCK %s via %s%s", ip, self.backend.name,
                     "" if self.enforce else " [PLAN]")
            return ok

    def sweep(self) -> int:
        """Unblock everything past its timeout. Returns count removed."""
        now = time.monotonic()
        with self._lock:
            expired = [ip for ip, e in self._blocked.items() if e.expires_at <= now]
        for ip in expired:
            self.unblock(ip)
        return len(expired)

    def active(self) -> "dict[str, float]":
        """Currently-blocked IPs -> seconds remaining."""
        now = time.monotonic()
        with self._lock:
            return {ip: round(e.expires_at - now, 1) for ip, e in self._blocked.items()}

    def close(self):
        """Stop the sweeper and flush every rule we added."""
        self._stop.set()
        if self._sweeper:
            self._sweeper.join(timeout=2)
        for ip in list(self._blocked):
            self.unblock(ip)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- internals ----------------------------------------------------------- #
    def _blockable(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            log.warning("refuse to block non-IP %r", ip)
            return False
        if ip in self.allow:
            return False
        return True

    def _ensure_setup(self):
        if self._setup_done:
            return
        for cmd in self.backend.setup_cmds():
            self._run(cmd, verb="setup", ip="-")
        self._setup_done = True

    def _run(self, cmd: list[str], *, verb: str, ip: str) -> bool:
        """Execute a firewall command, or just log it in plan mode."""
        printable = " ".join(cmd)
        if not self.enforce or not self.backend.executes:
            tag = "[PLAN]" if not self.enforce else "[LOG-ONLY]"
            log.info("%s %s %s: %s", tag, verb, ip, printable)
            return True
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception as e:  # pragma: no cover - env dependent
            log.error("%s %s failed to launch (%s): %s", verb, ip, e, printable)
            return False
        if r.returncode != 0:
            # nft "add" of an existing element, or setup of an existing table,
            # returns nonzero — tolerate those; surface anything else.
            msg = (r.stderr or "").strip()
            if verb == "setup" or "exists" in msg.lower():
                return True
            log.error("%s %s rc=%d: %s", verb, ip, r.returncode, msg or printable)
            return False
        return True

    def _start_sweeper(self):
        def loop():
            while not self._stop.wait(1.0):
                try:
                    n = self.sweep()
                    if n:
                        log.debug("sweeper unblocked %d expired IP(s)", n)
                except Exception as e:  # pragma: no cover
                    log.error("sweeper error: %s", e)
        self._sweeper = threading.Thread(target=loop, name="bastion-sweeper", daemon=True)
        self._sweeper.start()


# --------------------------------------------------------------------------- #
# Standalone demo — safe, no root, firewall untouched (plan mode).
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print(f"backend available: {pick_backend('auto').name} "
          f"(nft/iptables detected; staying in PLAN mode — nothing is touched)\n")

    b = Blocker(enabled=True, enforce=False, threshold=0.8, block_seconds=2)
    # A high-confidence DDoS flood -> BLOCKED (planned)
    print("1)", b.consider(AttackType.DDOS, 0.97, "10.0.0.5"))
    # Same IP again -> refresh, still BLOCKED
    print("2)", b.consider(AttackType.DOS, 0.91, "10.0.0.5"))
    # Low confidence -> LOGGED, not blocked
    print("3)", b.consider(AttackType.PROBE, 0.55, "10.0.0.6"))
    # Benign -> NONE
    print("4)", b.consider(AttackType.BENIGN, 0.99, "10.0.0.8"))
    # Loopback attack (spoofed/misclassified) -> refused, LOGGED
    print("5)", b.consider(AttackType.DDOS, 0.99, "127.0.0.1"))

    print("\nactive blocks (ip -> seconds left):", b.active())
    print("waiting for timeout + sweep...")
    time.sleep(2.2)
    removed = b.sweep()
    print(f"swept {removed} expired; active now:", b.active())
    b.close()
