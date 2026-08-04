"""
FilterEngine — Wireshark-style display filter for the `tshark` command.

Two layers:
  1. SimpleFilter   — exact-match on ip.src/ip.dst/tcp.port/udp.port/protocol
  2. DisplayFilter  — recursive-descent parser for the richer syntax in
                       the brief §6 (supports ==, !=, contains, and/or/not,
                       CIDR for ip.addr, and a few more).

FROZEN: simple filter semantics.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from typing import Callable, List, Optional

from .packet_metadata import PacketMetadata

logger = logging.getLogger(__name__)


class SimpleFilter:
    """Substring / exact-match filter applied to a packet list."""

    def __init__(self, expr: str = ""):
        self.expr = (expr or "").strip()
        self._compiled = self._compile(self.expr) if self.expr else None

    def _compile(self, expr: str) -> Optional[Callable[[PacketMetadata], bool]]:
        e = expr.lower()
        # ip.src / ip.dst / tcp.port / udp.port / protocol
        m = re.match(r"^ip\.src\s*==\s*(\S+)$", e)
        if m:
            target = m.group(1)
            return lambda pkt: pkt.src_ip == target
        m = re.match(r"^ip\.dst\s*==\s*(\S+)$", e)
        if m:
            target = m.group(1)
            return lambda pkt: pkt.dst_ip == target
        m = re.match(r"^ip\.addr\s*==\s*(\S+)$", e)
        if m:
            target = m.group(1)
            return lambda pkt: pkt.src_ip == target or pkt.dst_ip == target
        m = re.match(r"^tcp\.port\s*==\s*(\d+)$", e)
        if m:
            port = int(m.group(1))
            return lambda pkt: (pkt.protocol == "TCP" and
                                (pkt.src_port == port or pkt.dst_port == port))
        m = re.match(r"^udp\.port\s*==\s*(\d+)$", e)
        if m:
            port = int(m.group(1))
            return lambda pkt: (pkt.protocol == "UDP" and
                                (pkt.src_port == port or pkt.dst_port == port))
        m = re.match(r"^protocol\s*==\s*(\S+)$", e)
        if m:
            proto = m.group(1).upper()
            return lambda pkt: (pkt.protocol or "").upper() == proto
        m = re.match(r"^frame\.number\s*==\s*(\d+)$", e)
        if m:
            idx = int(m.group(1))
            return lambda pkt: pkt.index == idx
        # Fallback: substring match on stringified packet
        return lambda pkt: self.expr.lower() in pkt.short().lower()

    def apply(self, packets: List[PacketMetadata]) -> List[PacketMetadata]:
        if self._compiled is None:
            return list(packets)
        return [p for p in packets if self._compiled(p)]


# ---------------------------------------------------------------------------
# Recursive-descent parser for the richer display filter syntax
# ---------------------------------------------------------------------------

class _Tok:
    """Tiny tokenizer for the display filter mini-language."""
    def __init__(self, s: str):
        self.s = s
        self.pos = 0

    def peek(self) -> Optional[str]:
        if self.pos >= len(self.s):
            return None
        return self.s[self.pos]

    def consume(self) -> Optional[str]:
        ch = self.peek()
        if ch is not None:
            self.pos += 1
        return ch

    def skip_ws(self):
        while self.pos < len(self.s) and self.s[self.pos].isspace():
            self.pos += 1

    def match_word(self, w: str) -> bool:
        self.skip_ws()
        if self.s[self.pos:self.pos+len(w)].lower() == w.lower():
            self.pos += len(w)
            return True
        return False


class DisplayFilter:
    """Parses a single filter expression into a callable."""

    def __init__(self, expr: str):
        self.expr = expr.strip()
        self._fn = self._parse_or(_Tok(self.expr))

    def apply(self, packets):
        if self._fn is None:
            return list(packets)
        return [p for p in packets if self._fn(p)]

    # ---- grammar ----
    def _parse_or(self, tok: _Tok):
        tok.skip_ws()
        left = self._parse_and(tok)
        while True:
            tok.skip_ws()
            if tok.match_word("or"):
                right = self._parse_and(tok)
                left = (lambda l, r: (lambda pkt: l(pkt) or r(pkt)))(left, right)
            else:
                break
        return left

    def _parse_and(self, tok: _Tok):
        tok.skip_ws()
        left = self._parse_not(tok)
        while True:
            tok.skip_ws()
            if tok.match_word("and"):
                right = self._parse_not(tok)
                left = (lambda l, r: (lambda pkt: l(pkt) and r(pkt)))(left, right)
            else:
                break
        return left

    def _parse_not(self, tok: _Tok):
        tok.skip_ws()
        if tok.match_word("not") or tok.match_word("!"):
            inner = self._parse_atom(tok)
            return lambda pkt: not inner(pkt)
        return self._parse_atom(tok)

    def _parse_atom(self, tok: _Tok):
        tok.skip_ws()
        if tok.match_word("("):
            inner = self._parse_or(tok)
            tok.skip_ws()
            tok.match_word(")")  # best-effort
            return inner
        return self._parse_comparison(tok)

    def _parse_comparison(self, tok: _Tok):
        # <field> <op> <value>
        tok.skip_ws()
        field = _read_field(tok)
        tok.skip_ws()
        op = _read_op(tok)
        tok.skip_ws()
        value = _read_value(tok)
        return _build_predicate(field, op, value)


def _read_field(tok: _Tok) -> str:
    """Read a dotted field name (e.g. ip.src, tcp.flags.syn)."""
    tok.skip_ws()
    start = tok.pos
    while tok.pos < len(tok.s):
        ch = tok.s[tok.pos]
        if ch.isalnum() or ch in "._":
            tok.pos += 1
        else:
            break
    return tok.s[start:tok.pos]


def _read_op(tok: _Tok) -> str:
    tok.skip_ws()
    for op in ("==", "!=", "contains", "matches"):
        if tok.match_word(op):
            return op
    # Single = means ==
    if tok.peek() == "=":
        tok.consume()
        return "=="
    return "=="


def _read_value(tok: _Tok) -> str:
    tok.skip_ws()
    if tok.peek() == '"':
        tok.consume()
        start = tok.pos
        while tok.pos < len(tok.s) and tok.s[tok.pos] != '"':
            tok.pos += 1
        s = tok.s[start:tok.pos]
        if tok.peek() == '"':
            tok.consume()
        return s
    # Bareword until whitespace
    start = tok.pos
    while tok.pos < len(tok.s) and not tok.s[tok.pos].isspace():
        tok.pos += 1
    return tok.s[start:tok.pos]


def _build_predicate(field: str, op: str, value: str):
    """Map (field, op, value) to a (PacketMetadata) -> bool."""
    f = field.lower()
    if f == "ip.src":
        return _cmp(op, value, lambda p: p.src_ip)
    if f == "ip.dst":
        return _cmp(op, value, lambda p: p.dst_ip)
    if f == "ip.addr":
        # Either side matches
        return _cmp(op, value, lambda p: p.src_ip, alt_getter=lambda p: p.dst_ip)
    if f == "tcp.port":
        return _cmp(op, value, lambda p: p.src_port if p.protocol == "TCP" else None,
                    alt_getter=lambda p: p.dst_port if p.protocol == "TCP" else None)
    if f == "udp.port":
        return _cmp(op, value, lambda p: p.src_port if p.protocol == "UDP" else None,
                    alt_getter=lambda p: p.dst_port if p.protocol == "UDP" else None)
    if f == "tcp.srcport":
        return _cmp(op, value, lambda p: p.src_port if p.protocol == "TCP" else None)
    if f == "tcp.dstport":
        return _cmp(op, value, lambda p: p.dst_port if p.protocol == "TCP" else None)
    if f == "frame.number":
        return _cmp(op, value, lambda p: str(p.index))
    if f == "ip.proto":
        return _cmp(op, value, lambda p: str(p.ip_proto) if p.ip_proto is not None else "")
    if f == "tcp.flags.syn":
        return _flag_cmp(op, value, "S")
    if f == "tcp.flags.ack":
        return _flag_cmp(op, value, "A")
    if f == "tcp.flags.fin":
        return _flag_cmp(op, value, "F")
    if f == "tcp.flags.reset":
        return _flag_cmp(op, value, "R")
    # Fallback: substring on rendered packet
    return lambda p: value in p.short()


def _cmp(op: str, value: str, getter, alt_getter=None):
    """Compare; for tcp.port / udp.port / ip.addr, also check alt_getter."""
    if alt_getter is not None:
        # Match if either side satisfies the predicate.
        if op == "contains":
            def _c(p):
                a, b = getter(p), alt_getter(p)
                return (value in str(a or "")) or (value in str(b or ""))
            return _c
        if op == "matches":
            try:
                rx = re.compile(value)
                def _m(p):
                    a, b = getter(p), alt_getter(p)
                    return bool(rx.search(str(a or ""))) or bool(rx.search(str(b or "")))
                return _m
            except Exception:
                return lambda p: False
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
                def _eq(p):
                    for g in (getter(p), alt_getter(p)):
                        if not g:
                            continue
                        try:
                            if ipaddress.ip_address(g) in net:
                                return op != "!="
                        except Exception:
                            pass
                    return op == "!="  # none matched
                if op == "==":
                    return _eq
                if op == "!=":
                    return lambda p: not _eq(p)
            except Exception:
                pass
        # Plain string compare against either side.
        if op == "==":
            def _eq(p):
                a, b = getter(p), alt_getter(p)
                return str(a or "") == value or str(b or "") == value
            return _eq
        if op == "!=":
            def _neq(p):
                a, b = getter(p), alt_getter(p)
                return str(a or "") != value and str(b or "") != value
            return _neq
    # Single-getter path
    if op == "contains":
        return lambda p: (str(getter(p) or "").find(value) >= 0)
    if op == "matches":
        try:
            rx = re.compile(value)
            return lambda p: bool(rx.search(str(getter(p) or "")))
        except Exception:
            return lambda p: False
    if op == "!=":
        # CIDR-aware for ip.addr / ip.src / ip.dst
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
                def _neq(p):
                    got = getter(p)
                    if not got:
                        return False
                    try:
                        return ipaddress.ip_address(got) not in net
                    except Exception:
                        return True
                return _neq
            except Exception:
                pass
        return lambda p: str(getter(p) or "") != value
    # == (default). Support CIDR for ip fields.
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
            def _eq(p):
                got = getter(p)
                if not got:
                    return False
                try:
                    return ipaddress.ip_address(got) in net
                except Exception:
                    return False
            return _eq
        except Exception:
            pass
    return lambda p: str(getter(p) or "") == value


def _flag_cmp(op: str, value: str, flag: str):
    want = (value == "1" or value.lower() == "true")
    if op == "==":
        return lambda p: (flag in (p.tcp_flags or "")) == want
    if op == "!=":
        return lambda p: (flag in (p.tcp_flags or "")) != want
    return lambda p: False
