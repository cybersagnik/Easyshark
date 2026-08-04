#!/usr/bin/env python3
"""EasyShark PCAP test corpus downloader (Python equivalent of download_pcaps.sh)."""
import os
import sys
import urllib.request
import zipfile
import tarfile
import gzip
import shutil
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
OUT = ROOT / "PCAP_SAMPLES"
OUT.mkdir(exist_ok=True)
os.chdir(OUT)

BASE = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures"
GL_RAW = "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures"
EXTRA = "https://wiki.wireshark.org/uploads"


def have(name):
    for ext in ("", ".gz", ".tgz", ".zip", ".cap", ".pcap", ".pcapng"):
        if (OUT / f"{name}{ext}").exists():
            return True
    return False


def download(url, name=None):
    if name is None:
        name = url.rsplit("/", 1)[-1]
    dest = OUT / name
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  [skip] {name} ({dest.stat().st_size} bytes)")
        return True
    print(f"  [get ] {url} -> {name}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Easyshark/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
            shutil.copyfileobj(resp, f)
        return True
    except Exception as exc:
        print(f"  [FAIL] {name}: {exc}")
        if dest.exists():
            dest.unlink()
        return False


def ungz(path):
    """Decompress .gz -> bare file."""
    out = path.with_suffix("") if path.suffix == ".gz" else path.parent / (path.name + ".decompressed")
    if out.exists():
        return out
    print(f"  [ungz] {path.name}")
    with gzip.open(path, "rb") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return out


def unzip_to_here(path):
    print(f"  [unzip] {path.name}")
    with zipfile.ZipFile(path) as z:
        z.extractall(OUT)


def untar_to_here(path):
    print(f"  [untar] {path.name}")
    with tarfile.open(path) as t:
        t.extractall(OUT)


def section(title):
    print(f"\n=== {title} ===")


def batch(items, label):
    section(label)
    for url, name in items:
        download(url, name)


# --------------------------------------------------------------------------- #
# IPv6
# --------------------------------------------------------------------------- #
batch([
    (f"{BASE}/v6.pcap",                 "v6.pcap"),
    (f"{BASE}/v6-http.cap",             "v6-http.cap"),
    (f"{BASE}/FTPv6-1.cap",             "FTPv6-1.cap"),
    (f"{BASE}/FTPv6-2.cap",             "FTPv6-2.cap"),
    (f"{BASE}/DHCPv6.pcap",             "DHCPv6.pcap"),
], "IPv6")
if download(f"{BASE}/ipv6-ripng.gz", "ipv6-ripng.gz"):
    ungz(OUT / "ipv6-ripng.gz")
if download(f"{BASE}/rpl-dio-mc-nsa-optional-tlv-dissector-sample.pcap.gz",
            "rpl-dio.pcap.gz"):
    ungz(OUT / "rpl-dio.pcap.gz")

# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #
batch([
    (f"{GL_RAW}/tls12-dsb.pcapng",                       "tls12-dsb.pcapng"),
    (f"{GL_RAW}/tls13-20-chacha20poly1305.pcap",         "tls13-20-chacha20poly1305.pcap"),
    (f"{GL_RAW}/tls-renegotiation.pcap",                 "tls-renegotiation.pcap"),
    (f"{BASE}/ldap-ssl.pcapng",                          "ldap-ssl.pcapng"),
], "TLS")

# --------------------------------------------------------------------------- #
# HTTP/2 + WebSocket
# --------------------------------------------------------------------------- #
batch([
    (f"{GL_RAW}/http2-data-reassembly.pcap",  "http2-data-reassembly.pcap"),
    (f"{GL_RAW}/http2-h2c.pcap",             "http2-h2c.pcap"),
    (f"{GL_RAW}/websocket.pcap",             "websocket.pcap"),
], "HTTP/2 + WebSocket")
download("https://git.lekensteyn.nl/peter/wireshark-notes/plain/tls/http2-16-ssl.pcapng",
         "http2-16-ssl.pcapng")

# --------------------------------------------------------------------------- #
# SMB
# --------------------------------------------------------------------------- #
section("SMB")
for url, name in [
    (f"{BASE}/smbtorture.cap.gz",        "smbtorture.cap.gz"),
    (f"{BASE}/smb-on-windows-10.pcapng", "smb-on-windows-10.pcapng"),
    (f"{BASE}/smb3-aes-128-ccm.pcap",    "smb3-aes-128-ccm.pcap"),
    (f"{BASE}/smb311-aes-128-ccm-filt.pcap", "smb311-aes-128-ccm-filt.pcap"),
    (f"{BASE}/SMB-locking.pcapng.gz",    "SMB-locking.pcapng.gz"),
]:
    if download(url, name) and name.endswith(".gz"):
        ungz(OUT / name)
download("https://raw.githubusercontent.com/crynow0/pcap2hashes/main/tests/smb2.pcap",
         "smb2.pcap")

# --------------------------------------------------------------------------- #
# NTLM
# --------------------------------------------------------------------------- #
section("NTLM")
ok1 = download(f"{BASE}/create_two_tasks_then_enum_RPC_C_AUTHN_LEVEL_CONNECT_NTLMv2.pcapng",
               "ntlmssp-http-rpc.pcapng")
if not ok1:
    download(f"{EXTRA}/40d16f2106f8f5bd3e2b7bb19547f43e/"
             "create_two_tasks_then_enum_RPC_C_AUTHN_LEVEL_CONNECT_NTLMv2.pcapng",
             "ntlmssp-http-rpc.pcapng")

# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #
section("SSH")
for cipher in [
    "ssh_curve25519-aes128-gcm_opensshS",
    "ssh_curve25519-aes128-cbc_opensshS",
    "ssh_curve25519-aes256-gcm_opensshS",
]:
    download(f"{BASE}/{cipher}.pcapng", f"{cipher}.pcapng")

# --------------------------------------------------------------------------- #
# Kerberos
# --------------------------------------------------------------------------- #
section("Kerberos")
for url, name in [
    (f"{BASE}/krb-816.zip",            "krb-816.zip"),
    (f"{BASE}/krb5_tgs_fast.tgz",      "krb5_tgs_fast.tgz"),
    (f"{BASE}/kerberos-Delegation.zip", "kerberos-Delegation.zip"),
]:
    if download(url, name):
        if name.endswith(".zip"):
            try:
                unzip_to_here(OUT / name)
            except Exception as e:
                print(f"  [unzip fail] {e}")
        elif name.endswith(".tgz"):
            try:
                untar_to_here(OUT / name)
            except Exception as e:
                print(f"  [untar fail] {e}")
download("http://www.exumbraops.com/layerone2016/party/sample.krb.pcap",
         "kerberos-asrep-roast.pcap")

# --------------------------------------------------------------------------- #
# LDAP
# --------------------------------------------------------------------------- #
batch([
    (f"{BASE}/ldap-and-search.pcap",       "ldap-and-search.pcap"),
    (f"{BASE}/ldap-krb5-sign-seal-01.cap", "ldap-krb5-sign-seal-01.cap"),
], "LDAP")

# --------------------------------------------------------------------------- #
# RDP / CredSSP / Kerberos
# --------------------------------------------------------------------------- #
section("RDP / CredSSP")
if download(f"{EXTRA}/8c35b41dcf37fa3dd795e08f73f15991/ws-cssp.tgz",
            "ws-cssp.tgz"):
    try:
        untar_to_here(OUT / "ws-cssp.tgz")
    except Exception as e:
        print(f"  [untar fail] {e}")

# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
batch([
    (f"{EXTRA}/27707187aeb30df68e70c8fb9d614981/http.cap", "http.cap"),
    (f"{BASE}/http_with_jpegs.cap.gz",                     "http_with_jpegs.cap.gz"),
], "HTTP")
if (OUT / "http_with_jpegs.cap.gz").exists():
    try:
        ungz(OUT / "http_with_jpegs.cap.gz")
    except Exception as e:
        print(f"  [ungz fail] {e}")

# --------------------------------------------------------------------------- #
# NFS
# --------------------------------------------------------------------------- #
section("NFS")
for url, name in [
    (f"{BASE}/nfsv2.pcap.gz", "nfsv2.pcap.gz"),
    (f"{BASE}/nfsv3.pcap.gz", "nfsv3.pcap.gz"),
]:
    if download(url, name):
        try:
            ungz(OUT / name)
        except Exception as e:
            print(f"  [ungz fail] {e}")

# --------------------------------------------------------------------------- #
# SIP / RTP
# --------------------------------------------------------------------------- #
batch([
    (f"{BASE}/aaa.pcap",         "aaa.pcap"),
    (f"{BASE}/sip-rtp-g711.pcap", "sip-rtp-g711.pcap"),
], "SIP + RTP")

# --------------------------------------------------------------------------- #
# Ultimate grab bag
# --------------------------------------------------------------------------- #
section("Ultimate grab bag")
if download(f"{EXTRA}/26c41b5ec1d89343e2979b73ec374bc9/"
            "ultimate_wireshark_protocols_pcap_220213.pcap.zip",
            "ultimate_wireshark_protocols_pcap_220213.pcap.zip"):
    try:
        unzip_to_here(OUT / "ultimate_wireshark_protocols_pcap_220213.pcap.zip")
    except Exception as e:
        print(f"  [unzip fail] {e}")

print("\n=== Final inventory ===")
total_bytes = 0
for f in sorted(OUT.iterdir()):
    if f.is_file():
        size = f.stat().st_size
        total_bytes += size
        print(f"  {size:>12,d}  {f.name}")
print(f"\nTotal: {total_bytes:,d} bytes across {len(list(OUT.iterdir()))} entries")
