#!/usr/bin/env python3
"""NetMap: a live map of every device on your local network.

Run:  python3 netmap.py            (opens http://127.0.0.1:8765)
      python3 netmap.py --no-open  (don't open a browser)

Discovery uses only what this machine already has: a ping sweep, the kernel
ARP/neighbour table, mDNS (avahi-browse), reverse DNS and a short TCP port
probe. The web UI is served on localhost only.
"""
import ipaddress
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8765
SCAN_INTERVAL = 90  # seconds between automatic scans
DATA_DIR = os.path.join(os.path.expanduser("~"), ".local", "share", "netmap")
DATA_FILE = os.path.join(DATA_DIR, "devices.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
HISTORY_SECONDS = 48 * 3600
OUI_FILES = ["/usr/share/hwdata/oui.txt", "/usr/share/misc/oui.txt"]

PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 111: "RPC", 139: "NetBIOS", 853: "DNS over TLS",
    1080: "SOCKS proxy", 2049: "NFS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    8443: "HTTPS alt", 8888: "HTTP alt", 9000: "HTTP alt", 11434: "Ollama API", 27017: "MongoDB",
    22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB", 548: "AFP",
    554: "RTSP", 631: "IPP printing", 1883: "MQTT", 3389: "Remote Desktop",
    5000: "UPnP/Web", 5555: "ADB debugging", 5900: "VNC", 7000: "AirPlay",
    8008: "Cast", 8009: "Cast/DIAL", 8080: "HTTP alt", 8123: "Home Assistant",
    9100: "Raw printing", 32400: "Plex", 55442: "Fire TV remote",
    60000: "Fire TV DIAL", 62078: "Apple device sync",
}

# Ports commonly used by malware, backdoors, botnets or remote-control tools
SUSPICIOUS_PORTS = {
    1337: "common backdoor port", 2323: "alt Telnet (Mirai botnet)", 3128: "open proxy",
    4444: "Metasploit / backdoor default", 4899: "Radmin remote control", 5938: "TeamViewer",
    6667: "IRC (botnet command channel)", 7547: "TR-069 (Mirai target)", 9050: "Tor proxy",
    12345: "NetBus trojan", 20000: "remote-admin backdoor", 31337: "Back Orifice backdoor",
}
PORTS.update({p: n for p, n in SUSPICIOUS_PORTS.items() if p not in PORTS})

state_lock = threading.Lock()
events_lock = threading.Lock()
LIVE = {}    # device key -> deque[(ts, rtt_ms | None)], filled while the device is selected in the UI
EVENTS = {}  # ip -> deque[event] heard by the passive listener
scan_lock = threading.Lock()
MAX_ALERTS = 200
state = {"network": {}, "devices": {}, "aliases": {}, "trust": {}, "alerts": [], "settings": {"desktop_alerts": True},
         "history": {}, "gateway_mac": "",
         "scanning": False,
         "last_scan": None, "scan_count": 0, "error": None}


# ---------------------------------------------------------------- helpers
def sh(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def load_oui():
    table = {}
    for path in OUI_FILES:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.match(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", line.strip())
                if m:
                    table[m.group(1).replace("-", ":").lower()] = m.group(2).strip()
        break
    return table


OUI = load_oui()


def vendor_for(mac):
    if not mac:
        return ""
    if int(mac[1], 16) & 0x2:  # locally administered bit
        return "Private (randomized) MAC"
    return OUI.get(mac[:8].lower(), "")


def avahi_unescape(s):
    # avahi escapes bytes as \DDD (decimal), e.g. \032 = space, \226\128\153 = ’
    out, i = bytearray(), 0
    while i < len(s):
        if s[i] == "\\" and re.match(r"\d{3}", s[i + 1:i + 4]):
            out.append(int(s[i + 1:i + 4]))
            i += 4
        elif s[i] == "\\" and i + 1 < len(s):
            out += s[i + 1].encode()
            i += 2
        else:
            out += s[i].encode()
            i += 1
    return out.decode("utf-8", errors="replace")


def clean_host(h):
    h = (h or "").rstrip(".")
    for suffix in (".local", ".lan", ".home", ".attlocal.net", ".localdomain"):
        if h.endswith(suffix):
            h = h[: -len(suffix)]
    return h


# ---------------------------------------------------------------- discovery
def network_info():
    route = sh(["ip", "-4", "route", "show", "default"])
    m = re.search(r"default via (\S+) dev (\S+)", route)
    if not m:
        raise RuntimeError("No default IPv4 route found. Are you connected to a network?")
    gateway, iface = m.group(1), m.group(2)
    addr = sh(["ip", "-4", "-o", "addr", "show", "dev", iface])
    a = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", addr)
    if not a:
        raise RuntimeError(f"No IPv4 address on {iface}")
    iface_net = ipaddress.ip_interface(a.group(1))
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip().lower()
    except OSError:
        mac = ""
    return {"iface": iface, "gateway": gateway, "self_ip": str(iface_net.ip),
            "self_mac": mac, "subnet": str(iface_net.network),
            "hostname": socket.gethostname()}


def ping_sweep(net):
    """Ping every host; return {ip: ttl} for the ones that answered (TTL hints at the OS)."""
    hosts = list(ipaddress.ip_network(net["subnet"]).hosts())
    if len(hosts) > 1024:  # don't sweep huge subnets; rely on ARP + mDNS
        return {}

    def ping(ip):
        out = subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)],
                             capture_output=True, text=True).stdout
        m = re.search(r"ttl=(\d+)", out)
        t = re.search(r"time=([\d.]+)", out)
        return str(ip), (int(m.group(1)), float(t.group(1)) if t else None) if m else None

    with ThreadPoolExecutor(max_workers=128) as pool:
        return {ip: r for ip, r in pool.map(ping, hosts) if r}


def neighbours(net):
    found = {}
    for line in sh(["ip", "-4", "neigh", "show", "dev", net["iface"]]).splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+) lladdr ([0-9a-f:]{17}) (\S+)", line)
        if m and m.group(3) != "FAILED":
            found[m.group(1)] = m.group(2).lower()
    return found


def mdns(subnet):
    """Return {ip: {"names": set, "services": set, "hostname": str, "txt": dict}}."""
    result = {}
    try:
        p = subprocess.Popen(["avahi-browse", "-aprtk"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
    except FileNotFoundError:
        return result
    try:
        out, _ = p.communicate(timeout=12)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    net = ipaddress.ip_network(subnet)
    for line in out.splitlines():
        f = line.split(";")
        if len(f) < 9 or f[0] != "=" or f[2] != "IPv4":
            continue
        ip = f[7]
        try:
            if ipaddress.ip_address(ip) not in net:
                continue
        except ValueError:
            continue
        entry = result.setdefault(ip, {"names": set(), "services": set(), "hostname": "", "txt": {}})
        entry["names"].add(avahi_unescape(f[3]))
        entry["services"].add(f[4])
        entry["hostname"] = entry["hostname"] or avahi_unescape(f[6])
        txt = f[9] if len(f) > 9 else ""
        for k, v in re.findall(r'"([^"=]+)=([^"]*)"', txt):
            if k in ("n", "model", "md", "fn", "ty", "am"):
                entry["txt"].setdefault(k, avahi_unescape(v))
    return result


def router_devices(net):
    """Read the gateway's connected-device page (AT&T-style gateways serve it without a login).

    Returns {mac: {"ip", "name", "online", "conn"}}; empty if the router has no such page."""
    import html
    import urllib.request
    try:
        with urllib.request.urlopen(f'http://{net["gateway"]}/cgi-bin/devices.ha', timeout=15) as r:
            page = r.read().decode("utf-8", errors="ignore")
    except Exception:
        return {}
    lines = [l.strip() for l in html.unescape(re.sub(r"<[^>]+>", "\n", page)).splitlines() if l.strip()]
    found, cur = {}, None
    for i, line in enumerate(lines[:-2]):
        nxt = lines[i + 1]
        if line == "MAC Address" and re.fullmatch(r"[0-9a-f:]{17}", nxt):
            cur = found.setdefault(nxt, {"ip": "", "name": "", "online": False, "conn": ""})
        elif cur is None:
            continue
        elif line == "IPv4 Address / Name":
            cur["ip"], cur["name"] = nxt, lines[i + 2].lstrip("/ ").strip()
        elif line == "Name" and not cur["name"]:
            cur["name"] = nxt
        elif line == "Status":
            cur["online"] = nxt == "on"
        elif line == "Connection Type":
            cur["conn"] = f"{nxt} {lines[i + 2]}" if nxt == "Wi-Fi" else nxt
    for d in found.values():
        d["name"] = useful_router_name(d["name"])
    return found


def useful_router_name(name):
    # Drop placeholders the router invents: unknownXXXXXXXXXXXX, raw MACs, hashes, UUIDs, vendor strings
    if not name or re.fullmatch(r"unknown[0-9a-f]{12}|[0-9A-Fa-f]{12}|[0-9a-f]{32}|[0-9a-f-]{36}", name):
        return ""
    if re.search(r",? (LLC|Inc\.?|Ltd\.?|Corp\.?)$", name):
        return ""
    return name


def ddwrt_info(ip):
    """Read a DD-WRT router's public Info page: model, firmware, uptime, and its own Wi-Fi clients."""
    import html
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://{ip}/", timeout=6) as r:
            page = r.read().decode("utf-8", errors="ignore")
    except Exception:
        return None
    if "DD-WRT" not in page:
        return None
    text = html.unescape(re.sub(r"<[^>]+>", "\n", re.sub(r"<script.*?</script>", " ", page, flags=re.S)))
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    model = lines[lines.index("LAN MAC") - 1] if "LAN MAC" in lines else ""
    build = re.search(r"DD-WRT \(build (\d+)\)", page)
    uptime = re.search(r"up ([^,]+(?:,\s*\d+:\d+)?)", text)
    # DD-WRT masks client MACs (xx:xx:xx:xx:C0:14); keep the visible last two octets
    clients = [m.lower() for m in re.findall(r"setWirelessTable\('xx:xx:xx:xx:([0-9A-Fa-f:]{5})'", page)]
    return {"model": model, "firmware": f"DD-WRT build {build.group(1)}" if build else "DD-WRT",
            "uptime": uptime.group(1).strip() if uptime else "", "wifi_client_suffixes": clients}


def link_kind(conn):
    c = (conn or "").lower()
    if c.startswith("wi-fi") or "ghz" in c:
        return "wifi"
    if "ethernet" in c or c.startswith("lan"):
        return "wired"
    return "unknown"


def own_link(net):
    iface = net["iface"]
    if os.path.exists(f"/sys/class/net/{iface}/wireless"):
        return "wifi", "Wi-Fi"
    try:
        with open(f"/sys/class/net/{iface}/speed") as f:
            speed = int(f.read().strip())
        return "wired", f"Ethernet {speed} Mbps" if speed > 0 else "Ethernet"
    except (OSError, ValueError):
        return "wired", "Ethernet"


def build_topology(devs, routed, net):
    """Give each online device a parent (what it's plugged into / associated with) and a link type.

    The gateway's device list says who it sees directly and over which band. A device whose IP
    the gateway files under a *different* MAC sits behind a bridge that rewrites MACs (e.g. a
    DD-WRT client bridge); devices the gateway doesn't list as online at all are behind it too."""
    by_ip = {d["ip"]: d for d in devs}
    gw = by_ip.get(net["gateway"])
    if not gw:
        return
    gw.update(parent="", link="", link_detail="Internet gateway")
    online_router_macs = {mac for mac, r in routed.items() if r["online"]}

    # Find bridges: the gateway maps a device's IP to someone else's MAC
    bridges = {}  # bridge MAC as the gateway sees it -> bridge device
    for rmac, r in routed.items():
        dev = by_ip.get(r["ip"])
        if not (r["online"] and dev and dev["mac"] and dev["mac"] != rmac):
            continue
        # The bridge's LAN MAC is usually one or two off its radio MAC, so match on the first 5 octets
        bridge = next((d for d in devs if d["mac"][:14] == rmac[:14] and d is not dev), None) \
            or next((d for d in devs if d["type"] == "network"), None)
        if bridge:
            bridges[rmac] = bridge

    for rmac, bridge in bridges.items():
        info = ddwrt_info(bridge["ip"]) or {}
        conn = routed[rmac]["conn"]
        bridge.update(parent=gw["key"], link=link_kind(conn), is_bridge=True, bridge_info=info,
                      link_detail=conn)
    bridge_devs = list(bridges.values())

    for d in devs:
        if d is gw or d.get("is_bridge"):
            continue
        r = routed.get(d["mac"])
        behind = next((b for m, b in bridges.items() if routed[m]["ip"] == d["ip"]), None)
        if not behind and bridge_devs and routed and d["mac"] and d["mac"] not in online_router_macs:
            behind = bridge_devs[0]
        if d["is_self"]:
            kind, detail = own_link(net)
        elif behind:
            suffixes = behind.get("bridge_info", {}).get("wifi_client_suffixes", [])
            kind = "wifi" if d["mac"][-5:] in suffixes else "wired" if behind.get("bridge_info") else "unknown"
            detail = {"wifi": "Wi-Fi", "wired": "Ethernet"}.get(kind, "")
        elif r and r["online"]:
            kind, detail = link_kind(r["conn"]), r["conn"]
        else:
            kind, detail = "unknown", ""
        parent = behind or gw
        d.update(parent=parent["key"], link=kind, link_detail=detail)


def reverse_dns(ips):
    def lookup(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip, ""

    with ThreadPoolExecutor(max_workers=32) as pool:
        return dict(pool.map(lookup, ips))


def probe_ports(ips):
    def check(job):
        ip, port = job
        try:
            with socket.create_connection((ip, port), timeout=0.5):
                return ip, port
        except OSError:
            return ip, None

    jobs = [(ip, p) for ip in ips for p in PORTS]
    open_ports = {ip: [] for ip in ips}
    with ThreadPoolExecutor(max_workers=128) as pool:
        for ip, port in pool.map(check, jobs):
            if port:
                open_ports[ip].append(port)
    return open_ports


# ---------------------------------------------------------------- service fingerprinting
# Read-only: we connect, read what the service announces about itself, and hang up.
# No logins, no exploits.
HTTP_PORTS = {80, 5000, 8008, 8080, 8123, 8888, 9000, 11434, 32400}
HTTPS_PORTS = {443, 8443}


def _recv(sock, n=1024):
    try:
        return sock.recv(n)
    except OSError:
        return b""


def _http(ip, port, tls, path="/"):
    import ssl
    raw = socket.create_connection((ip, port), timeout=2.5)
    sock = raw
    cert_note = ""
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
            cert_note = "TLS"
        sock.settimeout(2.5)
        sock.sendall(f"GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetMap\r\n\r\n".encode())
        data = b""
        while len(data) < 32768:
            chunk = _recv(sock, 4096)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    text = data.decode("utf-8", errors="ignore")
    status = re.match(r"HTTP/\S+ (\d{3})", text)
    server = re.search(r"(?im)^server:\s*(.+)$", text)
    title = re.search(r"(?is)<title>\s*(.*?)\s*</title>", text)
    auth = re.search(r"(?im)^www-authenticate:\s*(\S+)", text)
    return {"status": int(status.group(1)) if status else 0,
            "server": server.group(1).strip()[:80] if server else "",
            "title": re.sub(r"\s+", " ", title.group(1))[:80] if title else "",
            "auth": auth.group(1) if auth else "", "tls": cert_note, "body": text[:4000]}


def fingerprint(ip, port):
    """Return {"port", "name", "banner", "facts"} describing what is listening."""
    info = {"port": port, "name": PORTS.get(port, ""), "banner": "", "facts": {}}
    try:
        if port in HTTP_PORTS or port in HTTPS_PORTS:
            h = _http(ip, port, port in HTTPS_PORTS)
            bits = [b for b in (h["server"], f'"{h["title"]}"' if h["title"] else "",
                                f'HTTP {h["status"]}' if h["status"] else "") if b]
            info["banner"] = " · ".join(bits)
            info["facts"] = {k: h[k] for k in ("status", "server", "title", "auth")}
            if port == 11434:
                info["facts"]["ollama_open"] = h["status"] == 200 and "ollama" in h["body"].lower()
        elif port == 5900:  # VNC: read the security types offered, then disconnect
            with socket.create_connection((ip, port), timeout=2.5) as sk:
                ver = _recv(sk, 12)
                if ver.startswith(b"RFB "):
                    sk.sendall(ver)
                    n = _recv(sk, 1)
                    types = list(_recv(sk, n[0])) if n and n[0] else []
                    names = {1: "no password", 2: "VNC password", 30: "Apple login", 35: "Apple login",
                             19: "VeNCrypt", 16: "Tight", 5: "RA2", 13: "RA2", 129: "Unix login"}
                    info["banner"] = f'{ver.decode(errors="ignore").strip()} · auth: ' + \
                        ", ".join(names.get(t, f"type {t}") for t in types)
                    info["facts"] = {"vnc_types": types}
        elif port == 6379:
            with socket.create_connection((ip, port), timeout=2.5) as sk:
                sk.sendall(b"PING\r\n")
                reply = _recv(sk, 64).decode(errors="ignore").strip()
                info["banner"] = reply[:60]
                info["facts"] = {"redis_open": reply.startswith("+PONG")}
        elif port in (21, 22, 23, 25):  # these speak first
            with socket.create_connection((ip, port), timeout=2.5) as sk:
                sk.settimeout(2.5)
                banner = _recv(sk, 256).decode("utf-8", errors="ignore")
                banner = re.sub(r"[^\x20-\x7e]", "", banner.splitlines()[0] if banner.strip() else "")
                info["banner"] = banner[:100] if len(banner.strip()) > 2 else ""
                m = re.search(r"OpenSSH_(\d+)\.(\d+)(?:p(\d+))?", banner)
                if m:
                    info["facts"]["openssh"] = [int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)]
    except Exception:
        pass
    return info


def fingerprint_all(open_ports):
    jobs = [(ip, p) for ip, ports in open_ports.items() for p in ports]
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda j: (j[0], fingerprint(*j)), jobs))
    out = {}
    for ip, info in results:
        out.setdefault(ip, []).append(info)
    for v in out.values():
        v.sort(key=lambda x: x["port"])
    return out


# ---------------------------------------------------------------- on-demand deep scan
# A wider, per-device audit the user triggers from the UI. Scans the common-TCP-port list
# below (vs. the small curated set the live loop uses), fingerprints what answers, and matches
# the result against known weaknesses — entirely offline (no external CVE lookups, no exploits).
DEEP_PORTS = sorted(set(PORTS) | {
    1, 7, 9, 13, 19, 20, 26, 37, 79, 81, 88, 106, 110, 113, 119, 135, 143, 144, 179, 199, 389,
    427, 444, 465, 513, 514, 515, 543, 544, 587, 646, 873, 990, 993, 995, 1024, 1025, 1026, 1027,
    1110, 1194, 1234, 1352, 1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2082, 2083, 2086,
    2087, 2095, 2096, 2121, 2222, 2375, 2376, 2379, 2483, 2484, 2601, 2604, 2638, 2967, 3000, 3128,
    3268, 3333, 3689, 3690, 3724, 4000, 4040, 4444, 4567, 4662, 4899, 5001, 5004, 5005, 5009, 5050,
    5060, 5101, 5190, 5222, 5269, 5357, 5601, 5631, 5666, 5800, 5901, 5984, 5985, 5986, 6000, 6001,
    6443, 6500, 6543, 6646, 6667, 6881, 6969, 7001, 7070, 7077, 7443, 7474, 7777, 8000, 8001, 8081,
    8083, 8086, 8088, 8089, 8181, 8333, 8500, 8545, 8686, 8765, 8787, 8800, 8834, 8880, 9001, 9042,
    9060, 9080, 9090, 9091, 9092, 9200, 9300, 9418, 9443, 9999, 10000, 11211, 27018, 28017, 49152,
    49153, 50000, 51413,
})


def deep_vulns(dcopy, net, router_open):
    """Known-weakness match over a device's (widened) open ports. Offline and advisory."""
    out = assess(dcopy, net, router_open)  # reuse every standard check
    seen = {f["title"] for f in out}
    ports = set(dcopy["ports"])
    svc = {s["port"]: s for s in dcopy.get("svc_detail", [])}

    def add(sev, title, detail, fix=""):
        if title in seen:
            return
        seen.add(title)
        out.append({"severity": sev, "title": title, "detail": detail, "fix": fix, "category": "vulnerability"})

    for p in sorted(ports):
        if p in SUSPICIOUS_PORTS:
            add("high", f"Suspicious port {p} open ({SUSPICIOUS_PORTS[p]})",
                "This port is commonly used by malware, backdoors or remote-control tools. Confirm you "
                "started whatever is listening here.", "If you don't recognise it, disconnect the device and scan it for malware.")
    if 3389 in ports:
        add("medium", "Remote Desktop (RDP) is exposed to the network",
            "RDP is a frequent target for brute-force and known exploits (e.g. BlueKeep on old Windows).",
            "Restrict RDP to Tailscale/VPN, require Network Level Authentication, and keep Windows updated.")
    if 2375 in ports or 2376 in ports:
        add("high", "Docker API is reachable over the network",
            "An open Docker API usually means anyone on the network can start containers and take over the host.",
            "Bind the Docker socket to localhost only; never expose 2375/2376 unauthenticated.")
    if 11211 in ports:
        add("high", "Memcached is open to the network",
            "Open Memcached can leak cached data and be abused for large DDoS amplification attacks.",
            "Bind Memcached to 127.0.0.1 and enable SASL auth if remote access is needed.")
    if 9200 in ports or 9300 in ports:
        add("high", "Elasticsearch is reachable from the network",
            "Elasticsearch has no auth by default — its indexes are often fully readable and writable.",
            "Put it behind authentication and bind it to localhost or a private interface.")
    if 2049 in ports:
        add("medium", "NFS file sharing is exported to the network",
            "NFS exports can expose files and are safe only when the export list and permissions are tight.",
            "Check /etc/exports; limit shares to specific hosts, or turn NFS off.")
    if 111 in ports:
        add("low", "RPC portmapper (port 111) is exposed",
            "The RPC mapper advertises other services (NFS, NIS) and is a common reconnaissance point.",
            "Firewall port 111 off from untrusted networks if you don't use NFS/NIS.")
    if 554 in ports:
        add("low", "Camera / RTSP stream reachable",
            "RTSP cameras frequently ship with default or no credentials and can be viewed by anyone who finds them.",
            "Set a strong camera password and keep its firmware updated.")
    if 1883 in ports:
        add("low", "MQTT broker is open",
            "Many MQTT brokers allow anonymous publish/subscribe, exposing or letting others control smart-home devices.",
            "Require a username/password on the broker and restrict it to your LAN.")
    if 9100 in ports:
        add("low", "Raw printing port (9100) is open",
            "Raw JetDirect printing lets anyone on the network print or probe the printer.",
            "Fine on a trusted home LAN; restrict it if the network is shared.")
    for p, s in svc.items():
        srv = (s.get("facts", {}).get("server") or "").lower()
        if re.search(r"apache/2\.[0-2]\.", srv):
            add("medium", "Outdated Apache web server", f"The web server reports '{srv}', a release line with known vulnerabilities.",
                "Update the device's web server / firmware.")
        elif re.search(r"\bnginx/1\.[0-9]\.", srv) and not re.search(r"nginx/1\.(1[0-9]|[2-9][0-9])", srv):
            add("medium", "Outdated nginx web server", f"The web server reports '{srv}', an old release line.",
                "Update the device's web server / firmware.")
    if len(ports) >= 12:
        add("low", f"Large attack surface — {len(ports)} open ports",
            "The more services a device exposes, the more ways in it offers. Many open ports on a home device is unusual.",
            "Turn off services you don't use.")
    out.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return out


def deep_scan(key):
    """Run a wider port scan + vuln match on one device. Returns the deep-scan result dict."""
    with state_lock:
        d = state["devices"].get(key)
        if not d:
            return None
        ip = d["ip"]
        base_ports = set(d.get("ports", []))
        base_sd = {s["port"]: s for s in d.get("svc_detail", [])}
        net = dict(state.get("network", {}))
        dsnap = dict(d)

    def check(p):
        try:
            with socket.create_connection((ip, p), timeout=0.6):
                return p
        except OSError:
            return None

    found = []
    with ThreadPoolExecutor(max_workers=200) as pool:
        for p in pool.map(check, DEEP_PORTS):
            if p:
                found.append(p)
    open_ports = sorted(base_ports | set(found))
    with ThreadPoolExecutor(max_workers=32) as pool:
        sd = list(pool.map(lambda p: base_sd.get(p) or fingerprint(ip, p), open_ports))
    sd.sort(key=lambda x: x["port"])

    dsnap["ports"] = open_ports
    dsnap["svc_detail"] = sd
    vulns = deep_vulns(dsnap, net, False)
    result = {"ts": time.time(), "scanned": len(DEEP_PORTS), "open": open_ports,
              "new_ports": sorted(set(found) - base_ports), "vulns": vulns}
    with state_lock:
        cur = state["devices"].get(key)
        if cur is not None:
            cur["deep"] = result
            save()
    return result


# ---------------------------------------------------------------- security checks
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def assess(d, net, router_page_open):
    """Rule-based checks against what we observed. Not a full vulnerability scan."""
    out = []
    add = lambda sev, title, detail, fix="": out.append(
        {"severity": sev, "title": title, "detail": detail, "fix": fix, "category": "vulnerability"})
    ports = set(d["ports"])
    svc = {s["port"]: s for s in d.get("svc_detail", [])}

    if 5555 in ports:
        add("high", "ADB debugging is open to the network",
            "Android Debug Bridge gives full control: installing apps, running commands, reading the "
            "screen. The device asks for approval the first time, but any computer allowed before "
            "gets straight in.", "Settings → My Fire TV / About → Developer options → turn off ADB debugging.")
    if 23 in ports:
        add("high", "Telnet is running", "Telnet sends passwords in plain text and is a favourite "
            "target for botnets.", "Turn off Telnet in the device's admin settings; use SSH instead.")
    if 21 in ports:
        add("medium", "FTP is running", "FTP sends logins and files unencrypted.",
            "Turn it off, or switch to SFTP.")
    if 5900 in ports:
        types = svc.get(5900, {}).get("facts", {}).get("vnc_types", [])
        if 1 in types:
            add("high", "Screen sharing (VNC) with NO password",
                "Anyone on the network can see and control this screen.",
                "Set a VNC password or turn screen sharing off.")
        elif types and set(types) <= {2}:
            add("medium", "Screen sharing (VNC) protected only by a VNC password",
                "Classic VNC passwords are limited to 8 characters and the session isn't encrypted.",
                "Use a long password, or only allow it over Tailscale/SSH.")
        else:
            add("low", "Screen sharing (VNC) is on",
                "Remote screen control is reachable from the network. It asks for a login.",
                "Turn it off if you don't use it.")
    if svc.get(6379, {}).get("facts", {}).get("redis_open"):
        add("high", "Redis database open with no password", "Anyone on the network can read or "
            "change the data, and often take over the machine.", "Set requirepass and bind Redis to localhost.")
    for p, label in ((3306, "MySQL"), (5432, "PostgreSQL"), (27017, "MongoDB")):
        if p in ports:
            add("medium", f"{label} database reachable from the network",
                "Databases are safer when only reachable from the machine itself.",
                f"Bind {label} to 127.0.0.1 unless other machines need it.")
    if svc.get(11434, {}).get("facts", {}).get("ollama_open"):
        add("medium", "Ollama AI API open without a password",
            "Anyone on the network can run your models or pull/delete them.",
            "Set OLLAMA_HOST=127.0.0.1, or put it behind a proxy with auth.")
    if 1080 in ports:
        add("medium", "Open proxy (SOCKS/HTTP) on port 1080",
            "Other devices can route traffic through this machine.",
            "Turn the proxy off or restrict who can use it.")
    if 445 in ports or 139 in ports:
        add("low", "Windows/SMB file sharing is on",
            "Shared folders are reachable from the network.",
            "Check which folders are shared and that guest access is off.")
    ssh = svc.get(22, {}).get("facts", {}).get("openssh")
    if ssh:
        v = (ssh[0], ssh[1])
        if (8, 5) <= v < (9, 8):
            add("medium", f"OpenSSH {ssh[0]}.{ssh[1]} may be affected by CVE-2024-6387 (regreSSHion)",
                "A remote code execution bug in OpenSSH 8.5–9.7 on Linux. Your OS may have patched it "
                "without changing the version number.", "Install system updates.")
        elif v < (8, 5):
            add("medium", f"Old OpenSSH {ssh[0]}.{ssh[1]}",
                "Versions this old have several known vulnerabilities.", "Install system updates.")
    if 22 in ports and "raspberry" in d["vendor"].lower():
        add("low", "SSH is on: make sure the default password is changed",
            "Older Raspberry Pi images (including RetroPie) ship with user pi / password raspberry.",
            "Log in and run passwd, or switch to SSH keys.")
    http_logins = [s for p, s in svc.items() if p in HTTP_PORTS and s["facts"].get("auth")]
    if http_logins:
        add("low", "Admin login over plain HTTP",
            "The password for the web interface is sent unencrypted on your network.",
            "Use the HTTPS version of the admin page if it has one.")
    bi = d.get("bridge_info") or {}
    build = re.search(r"build (\d+)", bi.get("firmware", ""))
    if build and int(build.group(1)) < 30000:
        add("high", f'Very old firmware ({bi["firmware"]}, from around 2009)',
            "This firmware has had no security updates in over 15 years and has publicly known "
            "vulnerabilities in its web interface. The WRT54G hardware is also limited to 54 Mbps.",
            "Replace it with a current Wi-Fi bridge / mesh node, or at least change the admin password "
            "and turn off remote management.")
    if bi:
        add("low", "Status page readable without a login",
            "The DD-WRT Info page shows model, firmware and connected clients to anyone on the network.",
            "Administration → Management → turn off 'Info Site' (or password-protect it).")
    if d["is_gateway"] and router_page_open:
        add("low", "Router's device list is readable without a login",
            "Anyone on your Wi-Fi can see every device's name, MAC and IP.",
            "Normal for AT&T gateways; keep the Wi-Fi password private and the guest network separate.")
    if 53 in ports and not d["is_gateway"] and d["type"] != "network":
        add("info", "Runs a DNS server", "This device answers DNS queries (e.g. Pi-hole).")
    out.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return out


# ---------------------------------------------------------------- device kind + operating system
def local_os_name():
    try:
        with open("/etc/os-release") as f:
            m = re.search(r'^PRETTY_NAME="?([^"\n]+)', f.read(), re.M)
            return m.group(1) if m else "Linux"
    except OSError:
        return "Linux"


def identify(d, net, alias=""):
    """Return (kind, os): e.g. ("iPhone", "iOS / iPadOS"), ("Windows PC", "Windows")."""
    # Real names only: our own placeholder names ("Phone/tablet") would feed back into the guess
    text = " ".join([alias, d.get("txt_name") or "", d.get("router_name", ""), d["hostname"],
                     " ".join(d["mdns_names"]), d.get("model", "")]).lower()
    v, svc, ports, ttl = d["vendor"].lower(), set(d["services"]), set(d["ports"]), d.get("ttl")
    banners = " ".join(s.get("banner", "") for s in d.get("svc_detail", [])).lower()
    model = d.get("model", "")

    # --- operating system
    if d["is_self"]:
        os_name = f"Linux ({local_os_name()})"
    elif d["is_gateway"]:
        os_name = "Router firmware"
    elif d.get("bridge_info") or "dd-wrt" in banners:
        os_name = "Linux (DD-WRT)"
    elif "_amzn-wplay._tcp" in svc or "fire tv" in text or {55442, 60000} <= ports:
        os_name = "Fire OS"
    elif re.search(r"iphone|ipad", text) or 62078 in ports:
        os_name = "iOS / iPadOS"
    elif re.search(r"mac ?mini|macbook|imac|mac pro|mac studio", text) or re.match(r"(Mac|iMac|MacBook)", model) \
            or (svc & {"_companion-link._tcp", "_airplay._tcp"} and d["type"] == "computer"):
        os_name = "macOS"
    elif re.search(r"android|galaxy|pixel|\bonn\b|tablet|kindle", text):
        os_name = "Android"
    elif m := re.search(r"(raspbian|ubuntu|debian|fedora|alpine|centos)", banners):
        os_name = f"Linux ({m.group(1).title()})"
    elif ttl and 100 < ttl <= 128 or any(x.startswith("_oculusal") for x in svc):  # Quest Link PC app is Windows-only
        os_name = "Windows"
    elif "raspberry" in v:
        os_name = "Linux"
    elif ttl and ttl > 200 and d["type"] in ("network", "router", "printer", "iot"):
        os_name = "Embedded"
    else:
        os_name = "Unknown"

    # --- device kind
    t = d["type"]
    if t == "router":
        kind = "Router"
    elif d.get("bridge_info") or (t == "network" and d.get("is_bridge")):
        kind = "Wi-Fi bridge"
    elif t == "network":
        kind = "Access point / switch"
    elif "iphone" in text:
        kind = "iPhone"
    elif "ipad" in text:
        kind = "iPad"
    elif os_name == "iOS / iPadOS":
        kind = "iPhone / iPad"
    elif os_name == "Fire OS":
        kind = "Fire TV"
    elif "_googlecast._tcp" in svc:
        kind = "Chromecast / Google TV"
    elif t == "tv":
        kind = "Smart TV"
    elif os_name == "Android":
        kind = "Android tablet" if re.search(r"tablet|\bonn\b|kindle|tab\b", text) else "Android phone"
    elif "raspberry" in v:
        kind = "Raspberry Pi"
    elif os_name == "macOS":
        kind = "Mac"
    elif os_name == "Windows":
        kind = "Windows PC"
    elif t == "computer":
        kind = "Linux PC" if os_name.startswith("Linux") else "Computer"
    elif t == "speaker":
        kind = "Echo / Alexa" if "amazon" in v else "Speaker"
    elif t == "phone":
        kind = "Phone / tablet"
    else:
        kind = {"printer": "Printer", "iot": "Smart home", "server": "Server"}.get(t, "Unknown")
    return kind, os_name


# ---------------------------------------------------------------- classification
def classify(d, net):
    svc = d["services"]
    v = d["vendor"].lower()
    text = " ".join([d["name"], d.get("router_name", ""), d["hostname"], " ".join(d["mdns_names"]), d.get("model", "")]).lower()
    ports = set(d["ports"])

    if d["ip"] == net["gateway"]:
        return "router"
    if d["ip"] == net["self_ip"]:
        return "computer"
    if "_amzn-wplay._tcp" in svc or "fire tv" in text or "_googlecast._tcp" in svc or "roku" in text \
            or {55442, 60000} <= ports or re.search(r"\btv\b|appletv|apple tv|bravia|webos", text):
        return "tv"
    if svc & {"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"} or 9100 in ports:
        return "printer"
    if any(x in v for x in ("linksys", "netgear", "ubiquiti", "eero", "humax", "arris", "aruba")):
        return "network"
    if "raspberry" in v or 8123 in ports:
        return "server"
    if re.search(r"mac ?mini|macbook|imac|mac pro|mac studio|desktop|laptop|-pc\b|thinkpad", text) \
            or svc & {"_ssh._tcp", "_sftp-ssh._tcp", "_smb._tcp", "_rfb._tcp", "_companion-link._tcp"} \
            or ports & {22, 445, 3389, 5900}:
        return "computer"
    if 62078 in ports or re.search(r"iphone|ipad|android|galaxy|pixel|tablet|\bonn\b|kindle|fire ?hd", text):
        return "phone"
    if "amazon" in v or "sonos" in v or "_spotify-connect._tcp" in svc or "_raop._tcp" in svc \
            or re.search(r"echo|alexa|homepod|sonos|speaker", text):
        return "speaker"
    if svc & {"_hap._tcp", "_matter._tcp", "_matterc._udp"} or 1883 in ports \
            or any(x in v for x in ("espressif", "tuya", "shelly", "signify", "philips lighting", "ecobee", "nest", "ring")):
        return "iot"
    if any(x in v for x in ("intel", "cloud network technology", "dell", "lenovo", "hewlett", "asustek", "micro-star", "realtek")):
        return "computer"
    if "apple" in v:
        return "phone"
    return "unknown"


TYPE_LABEL = {"router": "Router", "network": "Network gear", "computer": "Computer",
              "server": "Server / Pi", "phone": "Phone / tablet", "tv": "TV / streaming",
              "speaker": "Speaker / smart assistant", "printer": "Printer",
              "iot": "Smart home", "unknown": "Unknown"}


def best_name(d, net):
    if d["ip"] == net["self_ip"]:
        return f'{net["hostname"]} (this PC)'
    for candidate in (d.get("txt_name"), *sorted(d["mdns_names"], key=len)):
        if candidate and not re.fullmatch(r"[0-9A-F]{12}(@.*)?", candidate):
            return candidate
    if d["ip"] == net["gateway"]:
        return f'{short_vendor(d["vendor"]) or "Main"} router'.strip()
    if d.get("router_name") and not d["router_name"].startswith("amazon-"):
        return prettify(d["router_name"])
    host = clean_host(d["hostname"]) or clean_host(d["rdns"])
    if host and not host.startswith("_") and not re.fullmatch(r"\d+-\d+-\d+-\d+", host):
        return host
    vendor = short_vendor(d["vendor"])
    kind = {"phone": "Phone/tablet", "computer": "Computer", "tv": "TV", "speaker": "Smart speaker",
            "printer": "Printer", "server": "Server", "iot": "Smart device", "network": "Access point"}
    if vendor == "Amazon" and d["type"] == "speaker":
        return "Amazon Echo / Alexa"
    if vendor == "Apple" and d["type"] == "phone" or 62078 in d["ports"]:
        return "iPhone / iPad"
    if vendor:
        return f'{vendor} {kind.get(d["type"], "device").lower() if d["type"] != "unknown" else "device"}'
    if d["type"] != "unknown":
        return kind[d["type"]]
    return "Unknown device (private MAC)" if d["vendor"].startswith("Private") else "Unknown device"


def prettify(name):
    # "onn-8-Tablet" -> "onn 8 Tablet", "Julias-iPhone" -> "Julias iPhone"; leave other names alone
    if " " not in name and "-" in name and not re.search(r"\d+-\d+-\d+", name):
        name = name.replace("-", " ")
    return name


VENDOR_ALIASES = {"cloud network technology": "Foxconn", "hon hai": "Foxconn", "hewlett": "HP",
                  "cisco-linksys": "Linksys", "raspberry pi": "Raspberry Pi", "amazon": "Amazon",
                  "apple": "Apple", "intel": "Intel", "humax": "Humax", "samsung": "Samsung",
                  "espressif": "Espressif", "tp-link": "TP-Link", "google": "Google", "sonos": "Sonos"}


def short_vendor(v):
    if not v or v.startswith("Private"):
        return ""
    low = v.lower()
    for k, alias in VENDOR_ALIASES.items():
        if k in low:
            return alias
    v = re.sub(r"[,.]?\s+(inc|llc|ltd|co|corp|corporation|corporate|limited|gmbh|pte|technologies|technology)\b.*$", "", v, flags=re.I)
    return v.strip().title() if v.isupper() else v.strip()


# ---------------------------------------------------------------- scanning
def scan():
    if not scan_lock.acquire(blocking=False):
        return
    try:
        with state_lock:
            state["scanning"] = True
            # Only alert once we have a baseline; the very first scan just learns what's normal
            had_baseline = bool(state["devices"])
        net = network_info()
        pinged = ping_sweep(net)
        ttls = {ip: v[0] for ip, v in pinged.items()}
        rtts = {ip: v[1] for ip, v in pinged.items()}
        neigh = neighbours(net)
        neigh[net["self_ip"]] = net["self_mac"]
        md = mdns(net["subnet"])
        # mDNS can reveal hosts that dropped out of the ARP table; ping them so we get a MAC
        for ip in md:
            if ip not in neigh:
                subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        neigh.update({ip: mac for ip, mac in neighbours(net).items() if ip not in neigh})
        for ip in md:
            neigh.setdefault(ip, "")
        routed = router_devices(net)
        known_ips = set(neigh)
        for mac, r in routed.items():
            if r["online"] and r["ip"] and r["ip"] not in known_ips \
                    and ipaddress.ip_address(r["ip"]) in ipaddress.ip_network(net["subnet"]):
                neigh[r["ip"]] = mac
        ips = sorted(neigh, key=lambda x: ipaddress.ip_address(x))
        rdns = reverse_dns(ips)
        ports = probe_ports(ips)
        svc_detail = fingerprint_all(ports)
        now = time.time()

        with state_lock:
            devices = state["devices"]
            was_online = {k: dev.get("online", False) for k, dev in devices.items()}
            for dev in devices.values():
                dev["online"] = False
            for ip in ips:
                mac = neigh[ip]
                key = mac or f"ip:{ip}"
                m = md.get(ip, {"names": set(), "services": set(), "hostname": "", "txt": {}})
                prev = devices.get(key, {})
                d = {
                    "key": key, "ip": ip, "mac": mac, "vendor": vendor_for(mac),
                    "mdns_names": sorted(m["names"]), "services": set(m["services"]),
                    "hostname": m["hostname"], "rdns": rdns.get(ip, ""),
                    "router_name": routed.get(mac, {}).get("name", ""),
                    "connection": routed.get(mac, {}).get("conn", ""),
                    "txt_name": m["txt"].get("n") or m["txt"].get("fn") or m["txt"].get("ty"),
                    "model": m["txt"].get("model") or m["txt"].get("md") or m["txt"].get("am") or "",
                    "ports": sorted(ports.get(ip, [])), "svc_detail": svc_detail.get(ip, []), "name": "",
                    "first_seen": prev.get("first_seen", now), "last_seen": now, "online": True,
                    "ttl": ttls.get(ip) or prev.get("ttl"), "rtt": rtts.get(ip),
                    "ports_ever": sorted(set(prev.get("ports_ever", prev.get("ports", []))) | set(ports.get(ip, []))),
                    "changes": list(prev.get("changes", [])),
                    "is_self": ip == net["self_ip"], "is_gateway": ip == net["gateway"],
                    "new": had_baseline and not prev, "alerted_at": prev.get("alerted_at"),
                }
                d["type"] = classify(d, net)
                if d["type"] == "unknown" and prev.get("type") not in (None, "unknown"):
                    d["type"] = prev["type"]
                d["name"] = best_name(d, net)
                d["services"] = sorted(d["services"])
                if prev:
                    ch = d["changes"]
                    if not was_online.get(key) and state["scan_count"] > 0:  # not on NetMap's own restart
                        ch.append({"t": now, "text": "Came online", "sev": "info", "kind": "online"})
                    for p_ in sorted(set(d["ports"]) - set(prev.get("ports_ever", prev.get("ports", [])))):
                        bad = p_ in SUSPICIOUS_PORTS
                        ch.append({"t": now, "kind": "port", "sev": "high" if bad else "info",
                                   "flagged": bad,
                                   "text": f'New port opened: {p_} ({PORTS.get(p_, "unknown service")})',
                                   "fix": "If you didn't install something new on this device, investigate."})
                    if prev.get("ip") and prev["ip"] != ip:
                        ch.append({"t": now, "text": f'IP changed {prev["ip"]} → {ip}', "sev": "info", "kind": "ip"})
                    d["changes"] = ch[-100:]
                for k in ("parent", "link", "link_detail"):  # keep last known position until recomputed
                    d[k] = prev.get(k, "")
                devices[key] = d
            for k, dev in devices.items():
                if was_online.get(k) and not dev["online"]:
                    dev.setdefault("changes", []).append({"t": now, "text": "Went offline", "sev": "info", "kind": "offline"})
                    dev["changes"] = dev["changes"][-100:]
            # Router MAC changing is the classic sign of ARP spoofing (man-in-the-middle)
            gw_mac = neigh.get(net["gateway"], "")
            gw_dev = devices.get(gw_mac)
            if state["gateway_mac"] and gw_mac and gw_mac != state["gateway_mac"]:
                target = gw_dev or devices.get(state["gateway_mac"])
                if target is not None:
                    target.setdefault("changes", []).append({
                        "t": now, "kind": "security", "sev": "high", "flagged": True,
                        "text": f'Router hardware address changed ({state["gateway_mac"]} → {gw_mac})',
                        "fix": "If you didn't replace the router, someone may be intercepting traffic (ARP spoofing). "
                               "Disconnect unknown devices and change the Wi-Fi password."})
            if gw_mac:
                state["gateway_mac"] = gw_mac
            mac_ips = {}
            for ip_, mac_ in neigh.items():
                if mac_ and ip_ != net["self_ip"]:
                    mac_ips.setdefault(mac_, []).append(ip_)
            dup_macs = {m_: v for m_, v in mac_ips.items() if len(v) > 1}
            online = [d for d in devices.values() if d["online"]]
            for d in online:
                d.pop("is_bridge", None)
                d.pop("bridge_info", None)
        # DD-WRT lookups do network I/O, so build the topology outside the lock
        build_topology(online, routed, net)
        with state_lock:
            for d in online:
                if d.get("is_bridge") and not state["aliases"].get(d["key"]):
                    model = d["bridge_info"].get("model", "").split("/")[0]
                    d["name"] = f'{model or short_vendor(d["vendor"])} (Wi-Fi bridge)'
            for d in online:
                d["trust"] = state["trust"].get(d["key"], "")
                d["findings"] = assess(d, net, bool(routed)) + suspicious(d, dup_macs, now)
                d["findings"].sort(key=lambda f: SEV_ORDER[f["severity"]])
                d["kind"], d["os"] = identify(d, net, state["aliases"].get(d["key"], ""))
            fresh = []
            by_key = state["devices"]
            for d in online:
                if d.get("new"):
                    parent = by_key.get(d.get("parent", ""), {})
                    how = {"wifi": "Wi-Fi", "wired": "wired"}.get(d.get("link"), "")
                    a = {"id": f'{int(now * 1000)}-{d["key"]}', "time": now, "key": d["key"], "ip": d["ip"],
                         "mac": d["mac"], "name": d["name"], "kind": d.get("kind", ""), "vendor": d["vendor"],
                         "link_text": f'{how} via {parent.get("name", "")}'.strip() if parent else how,
                         "seen": False}
                    d["alerted_at"] = now
                    fresh.append(a)
                d["new"] = bool(d.get("alerted_at")) and now - d["alerted_at"] < 1800
            security = []
            for d in devices.values():
                for c in d.get("changes", []):
                    if c.get("sev") == "high" and c["t"] == now:
                        security.append({"id": f'{int(now * 1000)}-{d["key"]}-sec{len(security)}', "time": now,
                                         "key": d["key"], "ip": d["ip"], "mac": d["mac"], "name": d["name"],
                                         "kind": d.get("kind", ""), "vendor": d["vendor"], "link_text": "",
                                         "seen": False, "type": "security", "title": c["text"]})
            state["alerts"] = (security + fresh + state["alerts"])[:MAX_ALERTS]
            if fresh and state["settings"].get("desktop_alerts", True):
                desktop_notify(fresh)
            if security and state["settings"].get("desktop_alerts", True):
                notify_security(security)
            hist = state["history"]
            for k, dev in devices.items():
                h = hist.setdefault(k, [])
                h.append([round(now), 1 if dev["online"] else 0, dev.get("rtt") if dev["online"] else None])
                while h and h[0][0] < now - HISTORY_SECONDS:
                    h.pop(0)
            for d in devices.values():  # devices known from earlier scans but offline now
                if not d.get("kind") and "services" in d:
                    try:
                        d["kind"], d["os"] = identify(d, net, state["aliases"].get(d["key"], ""))
                    except (KeyError, TypeError):
                        pass
            state.update(network=net, last_scan=now, error=None)
            state["scan_count"] += 1
            save()
            save_history()
    except Exception as e:
        with state_lock:
            state["error"] = str(e)
    finally:
        with state_lock:
            state["scanning"] = False
        scan_lock.release()


# ---------------------------------------------------------------- passive listener
# Devices constantly broadcast small "who's there / here I am" messages (mDNS, SSDP, LLMNR).
# Listening to them is passive and shows what each device is doing in real time.
def _dns_name(d, o):
    labels, end = [], None
    for _ in range(64):
        if o >= len(d):
            break
        n = d[o]
        if n == 0:
            o += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = o + 2
            o = ((n & 0x3F) << 8) | d[o + 1]
            continue
        labels.append(d[o + 1:o + 1 + n].decode("utf-8", "replace"))
        o += 1 + n
    return ".".join(labels), (end if end is not None else o)


def _short(name):
    name = re.sub(r"\.local$", "", name)
    name = re.sub(r"\._(tcp|udp)$", "", name)
    return name.replace("._sub._", " / _")


def parse_dns_packet(d):
    """Return (is_response, asked_names, answered_names)."""
    flags, qd, an = struct.unpack(">HHH", d[2:8])
    o, asked, told = 12, [], []
    for _ in range(qd):
        n, o = _dns_name(d, o)
        o += 4
        asked.append(n)
    for _ in range(an):
        n, o = _dns_name(d, o)
        t, _c, _ttl, ln = struct.unpack(">HHIH", d[o:o + 10])
        o += 10
        told.append(_dns_name(d, o)[0] if t == 12 else n)
        o += ln
    return bool(flags & 0x8000), asked, told


def summarize_packet(proto, data):
    """Turn one broadcast packet into (text, flag) for the activity feed, or (None, None)."""
    try:
        if proto in ("mDNS", "LLMNR"):
            resp, asked, told = parse_dns_packet(data)
            names = sorted({_short(x) for x in (told if resp else asked) if x})
            if not names:
                return None, None
            more = f" +{len(names) - 3} more" if len(names) > 3 else ""
            flag = "low" if any("wpad" in n.lower() for n in names) else None
            if proto == "LLMNR":
                return (f'asked the network who "{names[0]}" is' if not resp else f"answered for {names[0]}"), flag
            return (f'announced {", ".join(names[:3])}{more}' if resp
                    else f'looked for {", ".join(names[:3])}{more}'), flag
        if proto == "SSDP":
            text = data.decode("utf-8", "ignore")
            first = text.split("\r\n", 1)[0]
            h = {l.split(":", 1)[0].upper(): l.split(":", 1)[1].strip() for l in text.split("\r\n") if ":" in l}
            if first.startswith("NOTIFY"):
                kind = "left" if "byebye" in h.get("NTS", "") else "announced"
                return f'UPnP {kind}: {h.get("NT", "")[:70]}' + (f' ({h["SERVER"][:40]})' if h.get("SERVER") else ""), None
            if first.startswith("M-SEARCH"):
                return f'searched for UPnP devices ({h.get("ST", "all")[:60]})', None
    except Exception:
        pass
    return None, None


def record_event(ip, proto, text, flag=None):
    now = time.time()
    with events_lock:
        q = EVENTS.setdefault(ip, deque(maxlen=150))
        # Collapse repeats: the same message within 2 minutes just bumps a counter
        for e in list(q)[-8:]:
            if e["proto"] == proto and e["text"] == text and now - e["t"] < 120:
                e["t"], e["count"] = now, e["count"] + 1
                return
        q.append({"t": now, "proto": proto, "text": text, "flag": flag, "count": 1})


def passive_listener():
    socks = []
    for grp, port, proto in (("224.0.0.251", 5353, "mDNS"), ("239.255.255.250", 1900, "SSDP"),
                             ("224.0.0.252", 5355, "LLMNR")):
        try:
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sk.bind(("", port))
            sk.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                          struct.pack("4s4s", socket.inet_aton(grp), socket.inet_aton("0.0.0.0")))
            socks.append((sk, proto))
        except OSError:
            pass  # e.g. port held exclusively by another service
    protos = {sk: proto for sk, proto in socks}
    while socks:
        ready, _, _ = select.select(list(protos), [], [], 5)
        for sk in ready:
            try:
                data, (ip, _port) = sk.recvfrom(9000)
            except OSError:
                continue
            text, flag = summarize_packet(protos[sk], data)
            if text:
                record_event(ip, protos[sk], text, flag)


def live_ping(ip):
    out = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True).stdout
    m = re.search(r"time=([\d.]+)", out)
    return float(m.group(1)) if m else None


def connections_with(ip):
    """Established TCP/UDP connections between this PC and the device."""
    out = []
    for line in sh(["ss", "-tunHp", "state", "established"]).splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local, peer = parts[3], parts[4]
        host = peer.rsplit(":", 1)[0].strip("[]").replace("::ffff:", "")
        if host != ip:
            continue
        proc = re.search(r'users:\(\("([^"]+)"', line)
        out.append({"proto": parts[0], "local": local, "peer": peer, "process": proc.group(1) if proc else ""})
    return out


def device_report(key):
    with state_lock:
        d = state["devices"].get(key)
        hist = list(state["history"].get(key, []))
        if not d:
            return None
        ip, online, changes = d["ip"], d["online"], list(d.get("changes", []))
    now = time.time()
    buf = LIVE.setdefault(key, deque(maxlen=90))
    if online:
        buf.append((now, live_ping(ip)))
    live = [p for p in buf if now - p[0] < 600]
    vals = [r for _, r in live if r is not None]
    day = [h for h in hist if h[0] >= now - 86400]
    buckets = []
    for i in range(48):  # 24 h in 30-minute slots; value = share of scans the device was online
        lo = now - 86400 + i * 1800
        pts = [h[1] for h in day if lo <= h[0] < lo + 1800]
        buckets.append(round(sum(pts) / len(pts), 2) if pts else None)
    scan_rtts = [h[2] for h in day if h[2]]
    with events_lock:
        events = list(EVENTS.get(ip, []))
    return {
        "key": key, "now": now,
        "live": [[round(t, 1), r] for t, r in live],
        "rtt_now": live[-1][1] if live else None,
        "rtt_avg": round(sum(vals) / len(vals), 1) if vals else None,
        "jitter": round(sum(abs(a - b) for a, b in zip(vals, vals[1:])) / (len(vals) - 1), 1) if len(vals) > 1 else None,
        "loss": round(100 * (len(live) - len(vals)) / len(live)) if live else None,
        "uptime_24h": round(100 * sum(h[1] for h in day) / len(day)) if day else None,
        "drops_24h": sum(1 for a, b in zip(day, day[1:]) if a[1] and not b[1]),
        "scan_rtt_avg": round(sum(scan_rtts) / len(scan_rtts), 1) if scan_rtts else None,
        "timeline": buckets,
        "events": events[-60:],
        "changes": changes[-60:],
        "connections": connections_with(ip) if online else [],
    }


def suspicious(d, dup_macs, now):
    """Behaviour-based flags (category "suspicious"), complementing assess()'s config checks."""
    out = []
    add = lambda sev, title, detail, fix="": out.append(
        {"severity": sev, "title": title, "detail": detail, "fix": fix, "category": "suspicious"})
    for p in d["ports"]:
        if p in SUSPICIOUS_PORTS:
            add("high", f"Port {p} is open ({SUSPICIOUS_PORTS[p]})",
                "This port is commonly used by malware, backdoors or remote-control tools. It can be "
                "legitimate software, but it's worth checking.",
                "Find which program listens on it on that device; if you don't recognise it, scan the device "
                "for malware and block the port.")
    if d["mac"] in dup_macs:
        add("medium", "Its hardware address also answers for other IPs",
            f'MAC {d["mac"]} is claimed by {", ".join(dup_macs[d["mac"]])}. This can be a device with two '
            "addresses, or a sign of ARP spoofing (someone intercepting traffic).",
            "Check that you recognise the device; if not, disconnect it and change your Wi-Fi password.")
    for c in d.get("changes", []):
        if c.get("sev") in ("high", "medium") and now - c["t"] < 86400 and c.get("flagged"):
            add(c["sev"], c["text"], "Recorded in the last 24 hours.", c.get("fix", ""))
    if d["name"].startswith("Unknown device") and not d.get("router_name") and not d.get("trust"):
        add("low", "Unidentified device",
            "It doesn't announce a name, maker or any services. Phones with private Wi-Fi addresses do this, "
            "but so would an intruder. Mark it trusted once you recognise it to silence this.",
            "Check the MAC against your devices' Wi-Fi settings, then rename it.")
    if len(d["ports"]) >= 8:
        add("low", f'{len(d["ports"])} open ports', "Lots of services means more ways in.",
            "Turn off services you don't use.")
    return out


def desktop_notify(new):
    """Pop a desktop notification (notify-send) for newly seen devices."""
    if not new:
        return
    if len(new) == 1:
        a = new[0]
        title = f'New device: {a["name"]}'
        body = f'{a["kind"]} · {a["ip"]}' + (f' · {a["vendor"]}' if a["vendor"] else "") + \
            (f'\n{a["link_text"]}' if a["link_text"] else "")
    else:
        title = f"{len(new)} new devices on your network"
        body = "\n".join(f'{a["name"]} · {a["ip"]}' for a in new[:6])
    try:
        subprocess.Popen(["notify-send", "-a", "NetMap", "-i", "network-wireless", "-u", "normal",
                          title, body], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        pass


def notify_security(items):
    for a in items[:3]:
        try:
            subprocess.Popen(["notify-send", "-a", "NetMap", "-i", "security-high", "-u", "critical",
                              f'⚠ {a["title"]}', f'{a["name"]} · {a["ip"]}'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            pass


def scan_loop():
    while True:
        scan()
        time.sleep(SCAN_INTERVAL)


def save():
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"devices": state["devices"], "aliases": state["aliases"], "trust": state["trust"],
                   "alerts": state["alerts"], "gateway_mac": state["gateway_mac"],
                   "settings": state["settings"]}, f, indent=1)
    os.replace(tmp, DATA_FILE)


def save_history():
    tmp = HISTORY_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state["history"], f, separators=(",", ":"))
    os.replace(tmp, HISTORY_FILE)


def load():
    try:
        with open(DATA_FILE) as f:
            data = json.load(f)
        for d in data.get("devices", {}).values():
            d["online"], d["new"] = False, False
        state["devices"] = data.get("devices", {})
        state["aliases"] = data.get("aliases", {})
        state["trust"] = data.get("trust", {})
        state["alerts"] = data.get("alerts", [])
        state["gateway_mac"] = data.get("gateway_mac", "")
        state["settings"].update(data.get("settings", {}))
    except (OSError, ValueError):
        pass
    try:
        with open(HISTORY_FILE) as f:
            state["history"] = json.load(f)
    except (OSError, ValueError):
        pass


def snapshot():
    with state_lock:
        devices = []
        for d in state["devices"].values():
            d = dict(d)
            d["alias"] = state["aliases"].get(d["key"], "")
            d["trust"] = state["trust"].get(d["key"], "")
            d["type_label"] = TYPE_LABEL.get(d["type"], "Unknown")
            d["port_names"] = {str(p): PORTS.get(p, "") for p in d["ports"]}
            devices.append(d)
        return {"network": state["network"], "devices": devices, "scanning": state["scanning"],
                "alerts": state["alerts"][:50], "unseen": sum(not a["seen"] for a in state["alerts"]),
                "settings": state["settings"],
                "last_scan": state["last_scan"], "error": state["error"], "now": time.time(),
                "interval": SCAN_INTERVAL}


# ---------------------------------------------------------------- web server
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self.send(200, PAGE, "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self.send(200, json.dumps(snapshot()))
        elif self.path.startswith("/api/device?"):
            from urllib.parse import parse_qs, urlparse
            key = parse_qs(urlparse(self.path).query).get("key", [""])[0]
            report = device_report(key)
            self.send(200, json.dumps(report)) if report else self.send(404, '{"error":"unknown device"}')
        else:
            self.send(404, '{"error":"not found"}')

    def do_POST(self):
        # Only accept requests from our own page (blocks other websites poking localhost)
        origin = self.headers.get("Origin", "")
        if origin and origin not in (f"http://{HOST}:{PORT}", f"http://localhost:{PORT}"):
            return self.send(403, '{"error":"forbidden"}')
        if self.path == "/api/scan":
            threading.Thread(target=scan, daemon=True).start()
            return self.send(202, '{"ok":true}')
        if self.path in ("/api/alerts/seen", "/api/alerts/clear"):
            with state_lock:
                if self.path.endswith("seen"):
                    for a in state["alerts"]:
                        a["seen"] = True
                else:
                    state["alerts"] = []
                save()
            return self.send(200, '{"ok":true}')
        if self.path == "/api/settings":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self.send(400, '{"error":"bad request"}')
            with state_lock:
                if "desktop_alerts" in body:
                    state["settings"]["desktop_alerts"] = bool(body["desktop_alerts"])
                save()
            return self.send(200, '{"ok":true}')
        if self.path == "/api/alias":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                key, name = str(body["key"]), str(body.get("name", "")).strip()[:60]
            except (ValueError, KeyError):
                return self.send(400, '{"error":"bad request"}')
            with state_lock:
                if name:
                    state["aliases"][key] = name
                else:
                    state["aliases"].pop(key, None)
                save()
            return self.send(200, '{"ok":true}')
        if self.path == "/api/trust":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                key, status = str(body["key"]), str(body.get("status", "")).strip()
            except (ValueError, KeyError):
                return self.send(400, '{"error":"bad request"}')
            if status not in ("", "trusted", "guest"):
                return self.send(400, '{"error":"bad status"}')
            with state_lock:
                if status:
                    state["trust"][key] = status
                else:
                    state["trust"].pop(key, None)
                dev = state["devices"].get(key)
                if dev is not None:
                    dev["trust"] = status
                    # Re-evaluate findings now so the Unidentified flag clears immediately
                    if dev.get("name", "").startswith("Unknown device"):
                        dev["findings"] = [f for f in dev.get("findings", [])
                                           if f.get("title") != "Unidentified device"] if status else dev.get("findings", [])
                save()
            return self.send(200, '{"ok":true}')
        if self.path == "/api/deepscan":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                key = str(body["key"])
            except (ValueError, KeyError):
                return self.send(400, '{"error":"bad request"}')
            result = deep_scan(key)
            return self.send(200, json.dumps(result)) if result else self.send(404, '{"error":"unknown device"}')
        self.send(404, '{"error":"not found"}')


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetMap</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#02060b;--panel:rgba(5,16,27,.82);--panel2:rgba(12,32,50,.55);--fg:#d6f4ff;--muted:#7393a8;--dim:#3b586b;
--line:rgba(56,225,255,.14);--line2:rgba(56,225,255,.38);--accent:#38e1ff;--accent2:#a78bfa;--ok:#2bff9a;--warn:#ffb020;--bad:#ff3b5c;
--mono:"JetBrainsMono NF","JetBrains Mono",ui-monospace,Menlo,monospace;--hud:"Orbitron","JetBrainsMono NF",ui-monospace,monospace;color-scheme:dark}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;min-height:100vh;color:var(--fg);font:13px/1.5 var(--mono);
background:radial-gradient(ellipse 70% 55% at 45% 0%,rgba(56,225,255,.11),transparent 70%),
radial-gradient(ellipse 50% 45% at 100% 100%,rgba(167,139,250,.09),transparent 70%),
linear-gradient(rgba(56,225,255,.035) 1px,transparent 1px) 0 0/44px 44px,
linear-gradient(90deg,rgba(56,225,255,.035) 1px,transparent 1px) 0 0/44px 44px,var(--bg)}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:50;opacity:.28;
background:repeating-linear-gradient(0deg,rgba(0,0,0,.5) 0 1px,transparent 1px 3px)}
::selection{background:rgba(56,225,255,.3)}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{background:var(--dim);border-radius:4px}::-webkit-scrollbar-track{background:transparent}
.g{font-family:"JetBrainsMono NF",var(--mono);font-style:normal}
/* ---------- header ---------- */
header{position:sticky;top:env(safe-area-inset-top,0px);z-index:5;display:flex;flex-wrap:wrap;gap:14px 26px;align-items:center;justify-content:space-between;
padding:12px 22px;background:linear-gradient(180deg,rgba(3,12,20,.96),rgba(3,12,20,.86));border-bottom:1px solid var(--line2);
box-shadow:0 1px 0 rgba(56,225,255,.08),0 10px 40px rgba(0,0,0,.5);backdrop-filter:blur(8px)}
header::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;
background:linear-gradient(90deg,transparent,var(--accent) 30%,var(--accent2) 70%,transparent);opacity:.8}
.brand{display:flex;gap:12px;align-items:center;min-width:0}
.logo{font-size:30px;color:var(--accent);text-shadow:0 0 14px rgba(56,225,255,.8);animation:breathe 3s ease-in-out infinite}
@keyframes breathe{50%{opacity:.55;text-shadow:0 0 4px rgba(56,225,255,.4)}}
h1{font:800 19px/1.1 var(--hud);margin:0;letter-spacing:.18em;color:#eafcff;text-shadow:0 0 18px rgba(56,225,255,.45)}
h1 span{font:500 10.5px var(--hud);letter-spacing:.22em;color:var(--accent);margin-left:10px;vertical-align:middle;opacity:.85}
.sub{color:var(--muted);font-size:11.5px;letter-spacing:.02em}
.stats{display:flex;gap:8px;flex-wrap:wrap}
.stat{position:relative;padding:5px 14px 6px;border:1px solid var(--line);background:var(--panel2);min-width:88px;
clip-path:polygon(8px 0,100% 0,100% calc(100% - 8px),calc(100% - 8px) 100%,0 100%,0 8px)}
.stat .k{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted)}
.stat .v{font:700 20px/1.1 var(--hud);font-variant-numeric:tabular-nums;color:#eafcff}
.stat .v.ok{color:var(--ok);text-shadow:0 0 12px rgba(43,255,154,.5)}
.stat .v small{font:600 11px var(--mono);color:var(--muted);margin-left:2px}
.threat .k b{margin-left:6px;font-weight:700}
.bars{display:flex;gap:3px;margin-top:5px}
.bars i{width:16px;height:12px;background:rgba(255,255,255,.07);transform:skewX(-18deg)}
.status{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.sysline{display:flex;gap:8px;align-items:center;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.clock{font:600 15px var(--hud);color:var(--accent);letter-spacing:.12em;font-variant-numeric:tabular-nums;text-shadow:0 0 10px rgba(56,225,255,.5)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block;box-shadow:0 0 8px var(--ok)}
.dot.busy{background:var(--warn);box-shadow:0 0 10px var(--warn);animation:blink .8s infinite}
@keyframes blink{50%{opacity:.25}}
/* ---------- controls ---------- */
button{font:600 11.5px var(--mono);letter-spacing:.1em;text-transform:uppercase;border:1px solid var(--line2);background:rgba(56,225,255,.04);
color:var(--fg);padding:7px 13px;cursor:pointer;transition:all .15s;
clip-path:polygon(6px 0,100% 0,100% calc(100% - 6px),calc(100% - 6px) 100%,0 100%,0 6px)}
button:hover{border-color:var(--accent);background:rgba(56,225,255,.12);color:#fff;box-shadow:inset 0 0 14px rgba(56,225,255,.25)}
button:disabled{opacity:.45;cursor:default}
button.primary{background:linear-gradient(90deg,rgba(56,225,255,.28),rgba(167,139,250,.28));border-color:var(--accent);color:#fff;
text-shadow:0 0 8px rgba(56,225,255,.8)}
button.primary:hover{background:linear-gradient(90deg,rgba(56,225,255,.45),rgba(167,139,250,.45))}
.bell{position:relative;font-size:16px;padding:4px 11px;clip-path:none}
.bell .cnt{position:absolute;top:-7px;right:-7px;background:var(--bad);color:#fff;border-radius:999px;font-size:10px;letter-spacing:0;
min-width:18px;height:18px;line-height:18px;padding:0 5px;font-weight:700;box-shadow:0 0 10px var(--bad)}
select{font:12px var(--mono);border:1px solid var(--line2);background:#06121d;color:var(--fg);padding:6px 8px;max-width:210px;outline:none}
select.on{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent),0 0 12px rgba(56,225,255,.3)}
input{font:12.5px var(--mono);border:1px solid var(--line2);background:rgba(2,10,18,.8);color:var(--fg);padding:7px 10px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 12px rgba(56,225,255,.25)}
input::placeholder{color:var(--dim)}
/* ---------- layout & panels ---------- */
main{display:grid;grid-template-columns:minmax(0,1fr) 410px;gap:16px;padding:16px 22px 24px;max-width:1600px;margin:0 auto;align-items:start}
main>section.card{position:sticky;top:calc(env(safe-area-inset-top,0px) + 92px)}
@media (max-width:980px){main{grid-template-columns:1fr;padding-inline:16px}main>section.card{position:relative;top:0}}
.card{position:relative;background:var(--panel);border:1px solid var(--line);box-shadow:inset 0 0 40px rgba(56,225,255,.04),0 8px 30px rgba(0,0,0,.45)}
.card::before,.card::after{content:"";position:absolute;width:16px;height:16px;pointer-events:none;border:2px solid var(--accent);opacity:.9}
.card::before{top:-1px;left:-1px;border-right:0;border-bottom:0}
.card::after{bottom:-1px;right:-1px;border-left:0;border-top:0}
.ptitle{display:flex;align-items:center;gap:8px;font:700 10.5px var(--hud);letter-spacing:.2em;text-transform:uppercase;color:var(--accent);
padding:10px 14px 0}
.ptitle::before{content:"";width:6px;height:6px;background:var(--accent);box-shadow:0 0 8px var(--accent)}
.ptitle::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}
aside{display:flex;flex-direction:column;gap:16px;min-width:0}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid var(--line)}
.selects{display:inline-flex;gap:8px;flex-wrap:wrap}
.seg{display:inline-flex;border:1px solid var(--line2);overflow:hidden}
.seg button{border:0;clip-path:none;padding:6px 12px;background:transparent;font-size:11px}
.seg button+button{border-left:1px solid var(--line)}
.seg button.on{background:rgba(56,225,255,.18);color:#fff;box-shadow:inset 0 -2px 0 var(--accent);text-shadow:0 0 8px rgba(56,225,255,.8)}
.seg .ct{opacity:.65;font-size:10.5px;margin-left:5px}
#risksum{font-size:11px;letter-spacing:.06em;text-transform:uppercase}
/* ---------- radar map ---------- */
#mapwrap{position:relative;min-height:420px;overflow:hidden}
#mapwrap .hud{position:absolute;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim);pointer-events:none;line-height:1.6}
#mapwrap .hud b{color:var(--accent);font-weight:600}
@media (max-width:640px){#mapwrap .hud{display:none}}
.hud.tl{top:10px;left:14px}.hud.tr{top:10px;right:14px;text-align:right}.hud.bl{bottom:10px;left:14px}.hud.br{bottom:10px;right:14px;text-align:right}
.zoomctl{position:absolute;right:12px;top:50%;transform:translateY(-50%);display:flex;flex-direction:column;gap:6px;align-items:center;z-index:4}
.zoomctl button{width:30px;height:30px;padding:0;border:1px solid var(--line2);background:var(--panel);color:var(--accent);border-radius:7px;font-size:17px;line-height:1;cursor:pointer;font-family:inherit;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);transition:background .15s,box-shadow .15s}
.zoomctl button:hover{background:var(--panel2);box-shadow:0 0 10px rgba(56,225,255,.35)}
.zoomctl button:active{transform:scale(.92)}
.zoomctl .zreset{font-size:14px}
.zoomctl .zlvl{font-size:9px;letter-spacing:.08em;color:var(--dim);font-variant-numeric:tabular-nums;pointer-events:none}
#map.grabbable{cursor:grab}#map.grabbing{cursor:grabbing}
.node.drill{cursor:pointer}
.crumbs{position:absolute;top:10px;left:14px;display:flex;align-items:center;gap:5px;flex-wrap:wrap;max-width:72%;z-index:5}
.crumbs .crumb{font-family:inherit;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);background:var(--panel);border:1px solid var(--line2);border-radius:6px;padding:3px 9px;cursor:pointer;backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);white-space:nowrap}
.crumbs .crumb:hover{background:var(--panel2);box-shadow:0 0 8px rgba(56,225,255,.3)}
.crumbs .crumb.cur{color:var(--fg);border-color:var(--accent);cursor:default;box-shadow:none}
.crumbs .sep{color:var(--dim);font-size:11px;line-height:1}
@media (max-width:640px){.zoomctl .zlvl{display:none}.zoomctl{right:8px}.crumbs{left:10px;max-width:92%}}
svg{display:block;width:100%;height:auto}
.ring{fill:none;stroke:rgba(56,225,255,.13);stroke-width:1}
.ring.mid{stroke-dasharray:2 6}
.ring.outer{stroke:rgba(56,225,255,.4);stroke-width:1.2}
.axis{stroke:rgba(56,225,255,.08);stroke-width:1}
.tick{stroke:rgba(56,225,255,.3);stroke-width:1}.tick.big{stroke:rgba(56,225,255,.7);stroke-width:1.5}
.deg{font:9px var(--mono);fill:rgba(56,225,255,.38);text-anchor:middle;dominant-baseline:central}
.sweepline{stroke:var(--accent);stroke-width:1.5;opacity:.75}
.link{stroke:var(--dim);stroke-width:1.2;opacity:.5;fill:none}
.link.live{stroke:var(--accent);opacity:.55}
.link.wired{stroke-width:2.2}
.link.wired.live{stroke-dasharray:7 5;animation:flow 1s linear infinite;opacity:.8}
.link.wifi{stroke-dasharray:2 6;stroke-linecap:round;stroke-width:2}
.link.wifi.live{animation:flow2 1.4s linear infinite}
.link.unknown{stroke-dasharray:1 7;opacity:.3}
.link.off{opacity:.12;animation:none}
.link.sel{stroke:#fff;opacity:1;filter:drop-shadow(0 0 4px var(--accent))}
@keyframes flow{to{stroke-dashoffset:-12}}@keyframes flow2{to{stroke-dashoffset:-8}}
.node{cursor:pointer}
.node .hx{fill:rgba(4,16,26,.94);stroke:var(--accent);stroke-width:1.5;transition:stroke-width .15s}
.node.online .hx{filter:url(#glow)}
.node:hover .hx{stroke-width:2.6}
.node.r-high .hx{stroke:var(--bad)}.node.r-medium .hx{stroke:var(--warn)}
.node.off .hx{stroke:var(--dim);filter:none}
.node.off{opacity:.42}
.node.ctx{opacity:.22}
.node .inner{fill:none;stroke:rgba(56,225,255,.18);stroke-width:1}
.node text.ic{font-family:"JetBrainsMono NF",monospace;text-anchor:middle;dominant-baseline:central;fill:#bff3ff;pointer-events:none}
.node.r-high text.ic{fill:#ffc2cc}.node.r-medium text.ic{fill:#ffe0a6}.node.off text.ic{fill:var(--muted)}
.node text.lb{font:600 10.5px var(--mono);letter-spacing:.06em;text-anchor:middle;fill:var(--fg);pointer-events:none;text-transform:uppercase;
paint-order:stroke;stroke:#02060b;stroke-width:3px}
.node text.ip{font:10px var(--mono);text-anchor:middle;fill:var(--accent);opacity:.75;pointer-events:none;paint-order:stroke;stroke:#02060b;stroke-width:3px}
.node.off text.ip{fill:var(--muted)}
.badge circle{fill:#04111c;stroke:var(--line2);stroke-width:1}
.badge text{font:9.5px "JetBrainsMono NF",monospace;fill:var(--accent);text-anchor:middle;dominant-baseline:central}
.risk text{font:13px "JetBrainsMono NF",monospace;text-anchor:middle;dominant-baseline:central}
.reticle{fill:none;stroke:#fff;stroke-width:1.5;stroke-dasharray:10 7;filter:drop-shadow(0 0 5px var(--accent))}
.pulse{fill:none;stroke:var(--ok);stroke-width:2;animation:pulse 1.8s infinite}
@keyframes pulse{0%{r:24;opacity:1}100%{r:44;opacity:0}}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;padding:10px 14px;border-top:1px solid var(--line);color:var(--muted);font-size:11px;letter-spacing:.04em}
.legend .g{color:var(--accent);margin-right:6px}
.lg-line{display:inline-block;width:26px;height:0;vertical-align:middle;margin-right:5px;border-top:2.2px dashed var(--accent)}
.lg-line.wifi{border-top:2px dotted var(--accent)}
.empty{padding:60px 20px;text-align:center;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;font-size:11.5px}
.err{color:var(--bad);padding:10px 22px;border-bottom:1px solid rgba(255,59,92,.3);background:rgba(255,59,92,.07)}
/* ---------- alerts & toast ---------- */
.alerts{padding-bottom:10px}
.alerts .ah{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding:8px 14px 6px}
.alerts .acts{display:flex;gap:6px;flex-wrap:wrap}
.alerts .acts button{padding:4px 9px;font-size:10.5px}
.al{display:flex;gap:10px;padding:8px 14px;border-top:1px solid var(--line);cursor:pointer;align-items:flex-start}
.al>.g{color:var(--accent);font-size:16px}
.al:hover{background:rgba(56,225,255,.06)}
.al.unseen{box-shadow:inset 3px 0 0 var(--ok)}
.al .t{font-size:12.5px;font-weight:600}
.al .m{font-size:11.5px;color:var(--muted)}
.alscroll{max-height:300px;overflow:auto}
.alerts .sub{padding:4px 14px}
.opt{display:flex;gap:6px;align-items:center;font-size:11.5px;color:var(--muted);margin:8px 14px 0}
.toast{position:fixed;right:20px;bottom:calc(20px + env(safe-area-inset-bottom,0px));background:rgba(4,16,26,.96);border:1px solid var(--ok);
padding:12px 16px;box-shadow:0 0 30px rgba(43,255,154,.25);max-width:340px;z-index:60;cursor:pointer;animation:tin .25s ease-out;
clip-path:polygon(10px 0,100% 0,100% calc(100% - 10px),calc(100% - 10px) 100%,0 100%,0 10px)}
.toast b{display:block;margin-bottom:2px;color:var(--ok);letter-spacing:.06em;text-transform:uppercase;font-size:12px}
@keyframes tin{from{transform:translateX(30px);opacity:0}}
/* ---------- device list ---------- */
.list .head{display:flex;gap:8px;padding:10px 14px}
.list .head input{flex:1;min-width:0}
.listscroll{max-height:440px;overflow:auto;padding-bottom:6px}
.row{display:flex;gap:10px;align-items:center;padding:6px 14px;cursor:pointer;border-left:2px solid transparent;font-size:12.5px;transition:background .12s}
.row>.g:first-child{color:var(--accent);width:16px;text-align:center}
.row:hover{background:linear-gradient(90deg,rgba(56,225,255,.1),transparent)}
.row.sel{border-left-color:var(--accent);background:linear-gradient(90deg,rgba(56,225,255,.16),transparent)}
.row.off{opacity:.45}.row.off>.g:first-child{color:var(--muted)}
.row .n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .lk{color:var(--muted);font-size:12px}
.row .i{color:var(--accent);opacity:.75;font-size:11.5px;font-variant-numeric:tabular-nums;min-width:92px;text-align:right}
.rdot{width:7px;height:7px;display:inline-block;flex:none;transform:rotate(45deg)}
/* ---------- detail ---------- */
.detail{padding:0 0 16px}
.detail .body{padding:4px 16px 0}
.detail .idle{padding:18px 16px 4px;color:var(--muted);font-size:12px}
.dhead{display:flex;gap:12px;align-items:center;margin:8px 0 12px}
.dhead .big{font-size:30px;color:var(--accent);text-shadow:0 0 14px rgba(56,225,255,.6);width:44px;height:44px;display:grid;place-items:center;
border:1px solid var(--line2);background:rgba(56,225,255,.06);clip-path:polygon(25% 0,75% 0,100% 50%,75% 100%,25% 100%,0 50%)}
.dhead h2{margin:0;font:700 15px/1.25 var(--mono);letter-spacing:.04em;word-break:break-word}
.dhead .tl{color:var(--muted);font-size:11.5px}
.gauge{margin-left:auto;flex:none;text-align:center;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.gauge svg{width:54px;height:54px;display:block}
.gauge .bgc{fill:none;stroke:rgba(255,255,255,.08);stroke-width:4}
.gauge .fgc{fill:none;stroke-width:4;stroke-linecap:butt;transform:rotate(-90deg);transform-origin:center}
.gauge .num{font:700 15px var(--hud);text-anchor:middle;dominant-baseline:central}
.sect{margin-top:16px}
.sect h3{display:flex;align-items:center;gap:8px;font:700 9.5px var(--hud);text-transform:uppercase;letter-spacing:.2em;color:var(--accent);margin:0 0 8px;opacity:.9}
.sect h3::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin:4px 0 10px}
.kpi{position:relative;background:rgba(56,225,255,.04);border:1px solid var(--line);padding:7px 4px;text-align:center}
.kpi::before{content:"";position:absolute;top:-1px;left:-1px;width:6px;height:6px;border-top:1px solid var(--accent);border-left:1px solid var(--accent)}
.kpi .v{font:700 15px var(--hud);font-variant-numeric:tabular-nums;color:#eafcff}
.kpi .k{font-size:9.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.12em}
.spark{width:100%;height:64px;display:block;background:rgba(2,10,18,.7);border:1px solid var(--line)}
.spark .grid{stroke:rgba(56,225,255,.07);stroke-width:1}
.spark .ln{fill:none;stroke:var(--accent);stroke-width:1.8;stroke-linejoin:round;filter:drop-shadow(0 0 3px var(--accent))}
.spark .ar{fill:url(#sparkfill)}
.spark .ls{stroke:var(--bad);stroke-width:2}
.spark text{font:9px var(--mono);fill:var(--muted)}
.sparkcap{display:flex;justify-content:space-between;font-size:10.5px;color:var(--muted);margin:3px 2px 0}
.tline{display:grid;grid-template-columns:repeat(48,1fr);gap:2px;height:20px;margin-top:4px}
.tline span{background:rgba(255,255,255,.06)}
.tline span.on{background:var(--ok);box-shadow:0 0 6px rgba(43,255,154,.5)}
.tline span.part{background:var(--ok);opacity:.45}
.tline span.off{background:var(--dim);opacity:.6}
.tcap{display:flex;justify-content:space-between;font-size:10px;color:var(--muted);margin-top:2px;letter-spacing:.06em}
.sev{display:inline-block;font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;padding:1px 7px;border:1px solid}
.sev.high{color:var(--bad);border-color:var(--bad);background:rgba(255,59,92,.12);box-shadow:0 0 10px rgba(255,59,92,.3)}
.sev.medium{color:var(--warn);border-color:var(--warn);background:rgba(255,176,32,.1)}
.sev.low{color:var(--accent);border-color:var(--accent);background:rgba(56,225,255,.08)}
.sev.info{color:var(--muted);border-color:var(--dim)}
.cat{display:inline-block;font-size:9.5px;border:1px solid var(--line2);padding:1px 7px;margin-left:5px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}
.cat.suspicious{border-color:var(--accent2);color:var(--accent2)}
.find{border-top:1px solid var(--line);padding:10px 0}
.find:first-of-type{border-top:0}
.find b{display:block;margin:5px 0 2px;font-size:12.5px}
.find p{margin:2px 0;font-size:11.5px;color:var(--muted)}
.find .fix{color:var(--fg)}
.find .fix::before{content:"▸ ";color:var(--ok)}
.svc{display:grid;grid-template-columns:62px 1fr;gap:2px 10px;font-size:12px;padding:5px 0;border-top:1px solid var(--line)}
.svc:first-of-type{border-top:0}
.svc .pt{color:var(--accent)}
.svc .bn{grid-column:2;color:var(--muted);font-size:11px;word-break:break-word}
.deepbtn{font-family:inherit;font-size:12px;letter-spacing:.04em;color:var(--accent);background:var(--panel2);border:1px solid var(--line2);border-radius:7px;padding:6px 13px;cursor:pointer;margin:2px 0 9px;transition:background .15s,box-shadow .15s}
.deepbtn:hover:not(:disabled){background:rgba(56,225,255,.16);box-shadow:0 0 10px rgba(56,225,255,.3)}
.deepbtn:disabled{opacity:.6;cursor:default}
.newp{display:flex;flex-wrap:wrap;gap:5px;margin:2px 0 9px}
.newp .pt{font-family:monospace;font-size:11px;color:var(--warn);background:rgba(255,176,32,.12);border:1px solid rgba(255,176,32,.4);border-radius:5px;padding:1px 7px}
.feed{max-height:300px;overflow:auto;border:1px solid var(--line);background:rgba(2,10,18,.6)}
.ev{display:grid;grid-template-columns:18px 1fr auto;gap:8px;padding:5px 10px;border-top:1px solid var(--line);font-size:11.5px;align-items:start}
.ev:first-child{border-top:0}
.ev>span{min-width:0;overflow-wrap:anywhere}
.ev>.g{color:var(--accent);text-align:center}
.ev .w{color:var(--muted);font-size:10.5px;white-space:nowrap;font-variant-numeric:tabular-nums}
.ev .p{color:var(--accent2);font-size:9.5px;text-transform:uppercase;letter-spacing:.1em;margin-right:6px}
.ev.high{background:rgba(255,59,92,.1)}.ev.high>.g{color:var(--bad)}
.ev.medium{background:rgba(255,176,32,.08)}.ev.medium>.g{color:var(--warn)}
.ev.low{background:rgba(56,225,255,.06)}
dl{margin:0;display:grid;grid-template-columns:104px 1fr;gap:6px 10px;font-size:12px}
dt{color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.1em;padding-top:2px}dd{margin:0;word-break:break-word}
.mono{color:var(--accent)}
.chip{display:inline-block;border:1px solid var(--line2);padding:1px 8px;margin:0 4px 4px 0;font-size:11px;background:rgba(56,225,255,.04)}
.chip.warn{border-color:var(--warn);color:var(--warn)}
.trustseg{display:flex;gap:0;border:1px solid var(--line2)}
.trustseg button{flex:1;border:0;clip-path:none;padding:7px 4px;background:transparent;font-size:10.5px}
.trustseg button+button{border-left:1px solid var(--line)}
.trustseg button.on[data-s="trusted"]{background:rgba(43,255,154,.16);color:#bfffdf;box-shadow:inset 0 -2px 0 var(--ok)}
.trustseg button.on[data-s="guest"]{background:rgba(167,139,250,.18);color:#e4dcff;box-shadow:inset 0 -2px 0 var(--accent2)}
.trustseg button.on[data-s=""]{background:rgba(115,147,168,.18);color:#cfe0ea;box-shadow:inset 0 -2px 0 var(--muted)}
.node .trust text{font:11px "JetBrainsMono NF",monospace;text-anchor:middle;dominant-baseline:central}
.node .trust circle{fill:#04111c;stroke-width:1}
.row .tb{font-size:13px;width:14px;text-align:center}
.rename{display:flex;gap:6px;margin-top:16px}
.rename input{flex:1;min-width:0}
@media (prefers-reduced-motion:reduce){*{animation:none!important}}
</style></head><body>
<svg width="0" height="0" style="position:absolute"><defs>
  <linearGradient id="sparkfill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#38e1ff" stop-opacity=".35"/><stop offset="1" stop-color="#38e1ff" stop-opacity="0"/></linearGradient>
</defs></svg>
<header>
  <div class="brand"><span class="logo g">&#xF0437;</span><div><h1>NETMAP<span>// SECURITY GRID</span></h1><div class="sub" id="netline">Discovering your network…</div></div></div>
  <div class="stats">
    <div class="stat"><div class="k">Online</div><div class="v ok" id="st-on">–</div></div>
    <div class="stat"><div class="k">Offline</div><div class="v" id="st-off">–</div></div>
    <div class="stat"><div class="k">Threats</div><div class="v" id="st-risk">–</div></div>
    <div class="stat threat"><div class="k">Threat level<b id="tl-name"></b></div><div class="bars" id="tl"><i></i><i></i><i></i><i></i><i></i></div></div>
  </div>
  <div class="status">
    <div><div class="clock" id="clock"></div><div class="sysline"><span class="dot busy" id="dot"></span><span id="statusline">Scanning…</span></div></div>
    <button class="bell g" id="bell" title="Alerts">&#xF009A;<span class="cnt" id="bellcnt" hidden></span></button>
    <button class="primary" id="scanbtn"><span class="g">&#xF0450;</span> Scan now</button></div>
</header>
<div class="err" id="err" hidden></div>
<main>
  <section class="card"><div class="toolbar"><div class="seg" id="seg">
      <button data-f="all" class="on">All<span class="ct" id="ct-all"></span></button>
      <button data-f="wifi"><span class="g">&#xF05A9;</span> Wi-Fi<span class="ct" id="ct-wifi"></span></button>
      <button data-f="wired"><span class="g">&#xF0200;</span> Wired<span class="ct" id="ct-wired"></span></button>
      <button data-f="issues"><span class="g">&#xF0026;</span> Issues<span class="ct" id="ct-issues"></span></button></div>
      <span class="selects"><select id="fkind" aria-label="Device type"></select><select id="fos" aria-label="Operating system"></select></span>
      <span class="sub" id="risksum"></span></div>
    <div id="mapwrap">
      <div class="hud tl">Network topology<br><b>● live</b> passive + active scan</div>
      <div class="crumbs" id="crumbs" hidden></div>
      <div class="hud tr" id="hud-tr"></div>
      <div class="hud bl" id="hud-bl"></div>
      <div class="hud br">Sweep 6 s<br>Ping 2 s · rescan <b id="hud-int"></b></div>
      <div class="zoomctl" id="zoomctl" hidden>
        <button data-z="in" title="Zoom in" aria-label="Zoom in">+</button>
        <button data-z="out" title="Zoom out" aria-label="Zoom out">&#8722;</button>
        <button data-z="reset" class="zreset" title="Reset view" aria-label="Reset view">&#9100;</button>
        <span class="zlvl">100%</span></div>
      <div class="empty" id="empty">First scan in progress, which takes about 20 seconds…</div><svg id="map" hidden></svg></div>
    <div class="legend" id="legend"></div></section>
  <aside>
    <div class="card alerts" id="alerts" hidden></div>
    <div class="card detail" id="detail"></div>
    <div class="card list"><div class="ptitle">Device registry</div><div class="head"><input id="filter" placeholder="Filter by name, IP, vendor…"></div>
      <div class="listscroll" id="list"></div></div>
  </aside>
</main>
<div class="toast" id="toast" hidden></div>
<script>
// Nerd Font glyphs (JetBrainsMono NF ships with Omarchy)
const G=c=>String.fromCodePoint(c);
const ICON={router:G(0xF0469),network:G(0xF0317),computer:G(0xF0379),server:G(0xF048B),phone:G(0xF011C),tv:G(0xF0502),
  speaker:G(0xF04C3),printer:G(0xF042A),iot:G(0xF0335),unknown:G(0xF0625)};
const LINK={wifi:G(0xF05A9),wired:G(0xF0200),unknown:"·"};
const ALERT=G(0xF0026);
const SHIELD=G(0xF0565), QUESTION=G(0xF0625);
const TRUST={trusted:{g:SHIELD,c:"#2bff9a",label:"Trusted"},guest:{g:G(0xF0b55),c:"#a78bfa",label:"Guest"}};
const ORDER=["network","computer","server","phone","tv","speaker","printer","iot","unknown"];
let LIVE=null, liveBusy=false, mapSize="", mapSig="";
// Topology zoom/pan. baseW/baseH are the fitted viewBox size; vz zoom, (vcx,vcy) view centre in svg coords.
let baseW=0, baseH=0, vz=1, vcx=0, vcy=0, didDrag=false;
// Drill-down: focusKey = node we've zoomed the tree into (null = whole network). hubSet = keys that have children.
let focusKey=null, hubSet=new Set();
let deepBusy=null; // key of the device currently running a deep scan
function select(k){sel=k;LIVE=null;render();pollLive()}
async function pollLive(){
  if(!sel||liveBusy)return; const k=sel; liveBusy=true;
  try{const r=await fetch("/api/device?key="+encodeURIComponent(k));if(r.ok&&sel===k){LIVE=await r.json();renderDetail()}}catch(e){}
  liveBusy=false;
}
let S=null, sel=null, filterText="", view="all", fkind="", fos="", showAlerts=false, lastAlertId=null, toastTimer=null;
try{view=localStorage.getItem("netmap.view")||"all";fkind=localStorage.getItem("netmap.kind")||"";fos=localStorage.getItem("netmap.os")||""}catch(e){}
const SEVC={high:"#ff3b5c",medium:"#ffb020",low:"#38e1ff",info:"#7393a8"};
const worst=d=>(d.findings||[]).map(f=>f.severity).sort((a,b)=>["high","medium","low","info"].indexOf(a)-["high","medium","low","info"].indexOf(b))[0]||"";
const issues=d=>(d.findings||[]).filter(f=>f.severity==="high"||f.severity==="medium");
const matchView=d=>view==="all"||(view==="issues"?issues(d).length>0:d.link===view);
const matches=d=>matchView(d)&&(!fkind||d.kind===fkind)&&(!fos||d.os===fos);
function fillSelect(id,field,label,cur){
  // Options come from what's on the network now; counts respect the other active filters
  const base=S.devices.filter(d=>matchView(d)&&(field==="kind"?(!fos||d.os===fos):(!fkind||d.kind===fkind)));
  const counts={};base.forEach(d=>{const k=d[field]||"Unknown";counts[k]=(counts[k]||0)+1});
  S.devices.forEach(d=>{const k=d[field]||"Unknown";if(!(k in counts))counts[k]=0});
  const opts=Object.keys(counts).sort((a,b)=>counts[b]-counts[a]||a.localeCompare(b));
  const el=$(id);if(document.activeElement===el)return;
  el.innerHTML=`<option value="">${label} (${base.length})</option>`+opts.map(k=>`<option value="${esc(k)}"${k===cur?" selected":""}>${esc(k)} (${counts[k]})</option>`).join("");
  el.classList.toggle("on",!!cur);
}
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const nameOf=d=>d.alias||d.name;
const linkText=d=>{const p=S.devices.find(x=>x.key===d.parent);
  return p?`${d.link_detail?d.link_detail+" → ":"via "}${nameOf(p)}`:(d.link_detail||"")};
const ago=t=>{if(!t)return"never";const s=Math.round(S.now-t);if(s<60)return s+"s ago";if(s<3600)return Math.round(s/60)+" min ago";if(s<86400)return Math.round(s/3600)+" h ago";return new Date(t*1000).toLocaleDateString()};
const ipNum=ip=>ip.split(".").reduce((a,b)=>a*256+ +b,0);
const LEVELS=[["",""],["Minimal","#2bff9a"],["Low","#38e1ff"],["Guarded","#ffb020"],["Elevated","#ff7a45"],["High","#ff3b5c"]];

async function load(){
  try{const r=await fetch("/api/state");S=await r.json();render()}catch(e){$("statusline").textContent="NetMap server not reachable"}
}
function render(){
  const n=S.network||{}, devs=S.devices;
  const on=devs.filter(d=>d.online).length;
  $("netline").textContent=n.subnet?`${n.subnet} · ${n.iface} · gateway ${n.gateway}`:"Discovering your network…";
  $("dot").className="dot"+(S.scanning?" busy":"");
  $("statusline").textContent=S.scanning?"Scanning…":`Last scan ${ago(S.last_scan)}`;
  $("scanbtn").disabled=S.scanning;
  $("err").hidden=!S.error; $("err").textContent=S.error?"Scan error: "+S.error:"";
  const live=S.devices.filter(d=>d.online);
  $("ct-all").textContent=live.length;
  $("ct-wifi").textContent=live.filter(d=>d.link==="wifi").length;
  $("ct-wired").textContent=live.filter(d=>d.link==="wired").length;
  $("ct-issues").textContent=S.devices.filter(d=>issues(d).length).length;
  document.querySelectorAll("#seg button").forEach(b=>b.classList.toggle("on",b.dataset.f===view));
  fillSelect("fkind","kind","All device types",fkind); fillSelect("fos","os","All systems",fos);
  const count=s=>S.devices.reduce((n,d)=>n+(d.findings||[]).filter(f=>f.severity===s).length,0);
  const hi=count("high"), me=count("medium"), lo=count("low");
  $("risksum").innerHTML=hi||me?`<span style="color:${SEVC.high}">${hi} high</span> · <span style="color:${SEVC.medium}">${me} medium</span> risks`:"No high or medium risks";
  // Header readouts
  $("st-on").textContent=on; $("st-off").textContent=devs.length-on;
  $("st-risk").innerHTML=`<span style="color:${hi?SEVC.high:me?SEVC.medium:"#eafcff"}">${hi+me}</span><small>${hi} hi · ${me} med</small>`;
  const lvl=hi>=3?5:hi?4:me?3:lo?2:1, [lname,lcol]=LEVELS[lvl];
  $("tl-name").textContent=lname; $("tl-name").style.color=lcol;
  [...$("tl").children].forEach((b,i)=>{b.style.background=i<lvl?lcol:"";b.style.boxShadow=i<lvl?`0 0 8px ${lcol}`:""});
  $("hud-tr").innerHTML=`Subnet <b>${esc(n.subnet||"—")}</b><br>Interface <b>${esc(n.iface||"—")}</b>`;
  $("hud-bl").innerHTML=`Nodes <b>${devs.length}</b> · online <b>${on}</b><br>Gateway <b>${esc(n.gateway||"—")}</b>`;
  $("hud-int").textContent=Math.round(S.interval/60*10)/10+" min";
  renderMap(); renderList(); renderDetail(); renderLegend(); renderAlerts();
}
function renderLegend(){
  const counts={};S.devices.forEach(d=>counts[d.type]=(counts[d.type]||0)+1);
  $("legend").innerHTML=["router",...ORDER].filter(t=>counts[t]).map(t=>{
    const d=S.devices.find(x=>x.type===t);return `<span><span class="g">${ICON[t]}</span>${esc(d.type_label)} (${counts[t]})</span>`}).join("")
    +`<span><span class="lg-line"></span>wired</span><span><span class="lg-line wifi"></span>Wi-Fi</span><span>dim = offline</span>`;
}
const hex=r=>[0,1,2,3,4,5].map(i=>{const a=Math.PI/3*i+Math.PI/6;return `${(Math.cos(a)*r).toFixed(1)},${(Math.sin(a)*r).toFixed(1)}`}).join(" ");
function radar(W,H,R,P){
  // Static backdrop: range rings, bearing ticks and a rotating sweep. Built once per size so the sweep never restarts.
  const O=R+22;
  let h=`<defs><radialGradient id="rg"><stop offset="0" stop-color="#38e1ff" stop-opacity=".12"/><stop offset=".7" stop-color="#38e1ff" stop-opacity=".03"/><stop offset="1" stop-color="#38e1ff" stop-opacity="0"/></radialGradient>
    <linearGradient id="sw" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#38e1ff" stop-opacity="0"/><stop offset="1" stop-color="#38e1ff" stop-opacity=".16"/></linearGradient>
    <filter id="glow" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="3.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
  const sx=P(0,1)[0];
  h+=`<ellipse rx="${O*sx}" ry="${O}" fill="url(#rg)"/>`;
  [[.23,""],[.46,"mid"],[.73,"mid"],[1,""],[O/R,"outer"]].forEach(([f,c])=>h+=`<ellipse class="ring ${c}" rx="${R*f*sx}" ry="${R*f}"/>`);
  h+=`<line class="axis" x1="${-O*sx}" x2="${O*sx}" y1="0" y2="0"/><line class="axis" x1="0" x2="0" y1="${-O}" y2="${O}"/>`;
  for(let a=0;a<360;a+=5){const t=a*Math.PI/180,big=a%30===0,[x1,y1]=P(t,O),[x2,y2]=P(t,O+(big?9:4));
    h+=`<line class="tick${big?" big":""}" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`;
    if(big&&(a<60||a>120)){const[x,y]=P(t,O+22);h+=`<text class="deg" x="${x}" y="${y}">${String((a+90)%360).padStart(3,"0")}</text>`}}
  const a1=-0.45;
  h+=`<g transform="scale(${sx},1)"><g><path d="M0,0L${O},0A${O},${O} 0 0,0 ${Math.cos(a1)*O},${Math.sin(a1)*O}Z" fill="url(#sw)"/>
    <line class="sweepline" x1="0" y1="0" x2="${O}" y2="0"/>
    <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="6s" repeatCount="indefinite"/></g></g>`;
  return h+`<g id="graph"></g>`;
}
function applyView(){
  const svg=$("map"); if(!baseW)return;
  const w=baseW/vz, h=baseH/vz;
  svg.setAttribute("viewBox",`${vcx-w/2} ${vcy-h/2} ${w} ${h}`);
  svg.classList.toggle("grabbable",vz>1);
  const l=$("zoomctl").querySelector(".zlvl"); if(l)l.textContent=Math.round(vz*100)+"%";
}
function clampView(){
  if(vz<=1){vz=1;vcx=0;vcy=0;return}
  if(vz>6)vz=6;
  const w=baseW/vz,h=baseH/vz,mx=(baseW-w)/2,my=(baseH-h)/2;
  vcx=Math.max(-mx,Math.min(mx,vcx)); vcy=Math.max(-my,Math.min(my,vcy));
}
function zoomBy(factor,cx,cy){
  const svg=$("map"),r=svg.getBoundingClientRect(); if(!baseW||!r.width)return;
  const nz=Math.min(6,Math.max(1,vz*factor)); if(nz===vz)return;
  let fx=.5,fy=.5; if(cx!=null){fx=(cx-r.left)/r.width; fy=(cy-r.top)/r.height}
  const w=baseW/vz,h=baseH/vz, px=vcx-w/2+fx*w, py=vcy-h/2+fy*h; // svg point under cursor
  const nw=baseW/nz,nh=baseH/nz;
  vz=nz; vcx=px-fx*nw+nw/2; vcy=py-fy*nh+nh/2; clampView(); applyView();
}
function resetView(){vz=1;vcx=0;vcy=0;applyView()}
function setFocus(k){focusKey=k||null;mapSig="";vz=1;vcx=0;vcy=0;renderMap()}
function focusPath(){
  if(!focusKey||!S)return [];
  const byK=new Map(S.devices.map(d=>[d.key,d])); const chain=[]; let c=byK.get(focusKey),g=0;
  while(c&&g++<12){chain.unshift(c);c=c.parent&&c.parent!==c.key?byK.get(c.parent):null}
  return chain;
}
function renderBreadcrumb(){
  const el=$("crumbs"),tl=document.querySelector(".hud.tl"); if(!el)return;
  if(!focusKey){el.hidden=true;el.innerHTML="";if(tl)tl.hidden=false;return}
  const chain=focusPath(); el.hidden=false; if(tl)tl.hidden=true;
  el.innerHTML=`<button class="crumb home" data-k="" title="Show the whole network">&#8962; Full network</button>`+
    chain.map(d=>`<span class="sep">&#9654;</span><button class="crumb${d.key===focusKey?" cur":""}" data-k="${esc(d.key)}">${esc(nameOf(d))}</button>`).join("");
  el.querySelectorAll("button").forEach(b=>b.onclick=()=>setFocus(b.dataset.k));
}
function renderMap(){
  const svg=$("map"); let devs=S.devices;
  if(!devs.length){svg.hidden=true;$("empty").hidden=false;return}
  svg.hidden=false;$("empty").hidden=true;
  const W=Math.max(300,$("mapwrap").clientWidth), H=W<600?W:Math.max(480,Math.min(820,W*.75));
  const small=W<600, R=Math.min(W,H)/2-(small?46:82), sx=W>H?Math.min(W/H*.95,1.6):1;
  const P=(a,r)=>[Math.cos(a)*r*sx,Math.sin(a)*r];
  if(mapSize!==W+"x"+H){mapSize=W+"x"+H;mapSig="";baseW=W;baseH=H;vz=1;vcx=0;vcy=0;svg.innerHTML=radar(W,H,R,P)}
  $("zoomctl").hidden=false; applyView();
  const all=S.devices, byKeyAll=new Map(all.map(d=>[d.key,d]));
  // Hubs: any device that is some other device's parent (over the whole network) — these are drillable.
  hubSet=new Set(); all.forEach(d=>{if(d.parent&&d.parent!==d.key&&byKeyAll.has(d.parent))hubSet.add(d.parent)});
  if(focusKey&&!byKeyAll.has(focusKey))focusKey=null; // focused node vanished → back to full view
  renderBreadcrumb();
  // Drill-down: when focused, restrict the tree to the focused node and everything behind it.
  const froot=focusKey?byKeyAll.get(focusKey):null;
  let sub=null;
  if(froot){sub=new Set([froot.key]);let ch=true;
    while(ch){ch=false;all.forEach(d=>{if(!sub.has(d.key)&&d.parent&&d.parent!==d.key&&sub.has(d.parent)){sub.add(d.key);ch=true}})}}
  // Keep every match plus the chain of devices it hangs off, so the tree stays readable
  const keep=new Set();
  all.forEach(d=>{if(sub&&!sub.has(d.key))return;
    if(!froot&&d.type==="router"){keep.add(d.key);return}
    if(!matches(d))return;let c=d,guard=0;
    while(c&&(!sub||sub.has(c.key))&&!keep.has(c.key)&&guard++<10){keep.add(c.key);c=byKeyAll.get(c.parent)}});
  if(froot)keep.add(froot.key);
  const ctx=k=>!matches(byKeyAll.get(k));
  devs=all.filter(d=>keep.has(d.key));
  const byKey=new Map(devs.map(d=>[d.key,d]));
  const root=froot||devs.find(d=>d.type==="router");
  const kids=new Map();
  devs.forEach(d=>{if(d===root)return;
    const p=byKey.has(d.parent)&&d.parent!==d.key?d.parent:(root?root.key:"");
    if(!kids.has(p))kids.set(p,[]);kids.get(p).push(d)});
  const sortK=a=>a.sort((x,y)=>ORDER.indexOf(x.type)-ORDER.indexOf(y.type)||ipNum(x.ip)-ipNum(y.ip));
  const top=sortK(kids.get(root?root.key:"")||[]);
  // Radial tree: hubs (devices with their own clients) sit on an inner ring, every leaf on the
  // outer ring; each hub gets an angular sector proportional to how many clients it has.
  const weight=d=>Math.max(1,(kids.get(d.key)||[]).length);
  const total=top.reduce((t,d)=>t+weight(d),0)||1;
  const pos=new Map(); if(root)pos.set(root.key,[0,0]);
  let cur=-Math.PI/2, leaf=0;
  const leafR=()=>total>16&&(leaf++%2)?R*.78:R;
  top.forEach(d=>{const sec=2*Math.PI*weight(d)/total, ch=sortK(kids.get(d.key)||[]);
    if(ch.length){pos.set(d.key,P(cur+sec/2,R*.46));
      ch.forEach((c,j)=>pos.set(c.key,P(cur+(j+.5)*sec/ch.length,leafR())))}
    else pos.set(d.key,P(cur+sec/2,leafR()));
    cur+=sec});
  devs.forEach(d=>{if(!pos.has(d.key))pos.set(d.key,[0,0])});
  let h="";
  devs.forEach(d=>{if(d===root)return;const pk=byKey.has(d.parent)?d.parent:root&&root.key;if(!pk)return;
    const[x1,y1]=pos.get(pk),[x2,y2]=pos.get(d.key), on=d.online&&byKey.get(pk).online;
    h+=`<line class="link ${d.link||"unknown"}${on?" live":" off"}${sel===d.key||sel===pk?" sel":""}" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`});
  devs.forEach(d=>{const[x,y]=pos.get(d.key);const nm=nameOf(d);
    const lb=nm.length>19?nm.slice(0,18)+"…":nm, big=d===root, hub=(kids.get(d.key)||[]).length>0&&!big;
    const r=small?(big?24:hub?20:15):big?32:hub?27:22;
    const w=worst(d), showRisk=w==="high"||w==="medium";
    h+=`<g class="node${d.online?" online":" off"}${showRisk?" r-"+w:""}${sel===d.key?" sel":""}${view!=="all"&&ctx(d.key)?" ctx":""}" data-k="${esc(d.key)}" transform="translate(${x},${y})">
      ${d.new&&d.online?'<circle class="pulse" r="24"/>':""}
      ${sel===d.key?`<circle class="reticle" r="${r+10}"><animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="8s" repeatCount="indefinite"/></circle>`:""}
      <polygon class="hx" points="${hex(r)}"/>${big||hub?`<polygon class="inner" points="${hex(r-5)}"/>`:""}
      <text class="ic" style="font-size:${small?(big?18:13):big?24:hub?20:17}px">${ICON[d.type]||ICON.unknown}</text>
      ${!big&&d.link&&d.link!=="unknown"?`<g class="badge" transform="translate(${r*.8},${-r*.62})"><circle r="8"/><text>${LINK[d.link]}</text></g>`:""}
      ${showRisk?`<g class="risk" transform="translate(${-r*.8},${-r*.62})"><text fill="${SEVC[w]}" style="filter:drop-shadow(0 0 4px ${SEVC[w]})">${ALERT}</text></g>`:""}
      ${!big&&TRUST[d.trust]?`<g class="trust" transform="translate(${-r*.8},${r*.62})"><circle r="8" stroke="${TRUST[d.trust].c}"/><text fill="${TRUST[d.trust].c}">${TRUST[d.trust].g}</text></g>`:""}
      ${small&&!big?"":`<text class="lb" y="${r+15}">${esc(lb)}</text><text class="ip" y="${r+28}">${esc(d.ip)}</text>`}
      <title>${esc(nm)} · ${esc(d.ip)}${linkText(d)?" · "+esc(linkText(d)):""}${hubSet.has(d.key)?" · double-click to focus":""}</title></g>`});
  // Only touch the DOM when something changed, so link and reticle animations run smoothly
  if(h===mapSig)return; mapSig=h;
  const g=$("graph"); g.innerHTML=h;
  g.querySelectorAll(".node").forEach(n=>{n.onclick=()=>{if(didDrag)return;select(n.dataset.k)};
    n.ondblclick=()=>{if(hubSet.has(n.dataset.k))setFocus(n.dataset.k)};
    if(hubSet.has(n.dataset.k))n.classList.add("drill")});
}
function renderAlerts(){
  const A=S.alerts||[];
  $("bellcnt").hidden=!S.unseen; $("bellcnt").textContent=S.unseen>99?"99+":S.unseen;
  // Toast for alerts that arrived while the page is open
  if(lastAlertId!==null&&A.length&&A[0].id!==lastAlertId){
    const fresh=A.slice(0,A.findIndex(a=>a.id===lastAlertId)>=0?A.findIndex(a=>a.id===lastAlertId):A.length);
    const t=$("toast");
    t.innerHTML=fresh.length===1?`<b>New device: ${esc(fresh[0].name)}</b><span class="sub">${esc(fresh[0].kind)} · ${esc(fresh[0].ip)}${fresh[0].link_text?" · "+esc(fresh[0].link_text):""}</span>`
      :`<b>${fresh.length} new devices joined</b><span class="sub">${fresh.slice(0,4).map(a=>esc(a.name)).join(", ")}</span>`;
    t.hidden=false; t.onclick=()=>{t.hidden=true;select(fresh[0].key)};
    clearTimeout(toastTimer); toastTimer=setTimeout(()=>t.hidden=true,9000);
  }
  lastAlertId=A.length?A[0].id:"";
  const box=$("alerts"); box.hidden=!showAlerts; if(!showAlerts)return;
  if(box.contains(document.activeElement))return;
  box.innerHTML=`<div class="ptitle">Alerts</div><div class="ah"><div class="acts">
      <button id="aseen">Mark read</button><button id="aclear">Clear</button><button id="aclose">✕</button></div></div>
    <div class="alscroll">${A.length?A.map(a=>{const d=S.devices.find(x=>x.key===a.key);
      return `<div class="al${a.seen?"":" unseen"}" data-k="${esc(a.key)}"><span class="g">${ICON[d?d.type:"unknown"]||ICON.unknown}</span><div>
      <div class="t">${a.type==="security"?`<span style="color:${SEVC.high}"><span class="g">${ALERT}</span> ${esc(a.title)}</span>`:esc(d?nameOf(d):a.name)}</div>
      ${a.type==="security"?`<div class="m">${esc(d?nameOf(d):a.name)}</div>`:""}
      <div class="m">${esc(a.kind||"")} · ${esc(a.ip)}${a.vendor?" · "+esc(a.vendor):""}${a.link_text?" · "+esc(a.link_text):""}</div>
      <div class="m">joined ${ago(a.time)}${d&&!d.online?" · now offline":""}</div></div></div>`}).join("")
      :`<p class="sub">No new devices yet. You'll be alerted here and on your desktop when one joins.</p>`}</div>
    <label class="opt"><input type="checkbox" id="adesk" ${S.settings&&S.settings.desktop_alerts?"checked":""}> Desktop notifications</label>`;
  box.querySelectorAll(".al").forEach(r=>r.onclick=()=>select(r.dataset.k));
  $("aseen").onclick=async()=>{await fetch("/api/alerts/seen",{method:"POST"});load()};
  $("aclear").onclick=async()=>{await fetch("/api/alerts/clear",{method:"POST"});load()};
  $("aclose").onclick=()=>{showAlerts=false;render()};
  $("adesk").onchange=async e=>{await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({desktop_alerts:e.target.checked})});load()};
}
function renderList(){
  const f=filterText.toLowerCase();
  const devs=S.devices.filter(matches).filter(d=>!f||[nameOf(d),d.ip,d.mac,d.vendor,d.type_label,d.hostname,d.kind,d.os].join(" ").toLowerCase().includes(f))
    .sort((a,b)=>(b.online-a.online)||ipNum(a.ip)-ipNum(b.ip));
  $("list").innerHTML=devs.map(d=>`<div class="row${d.online?"":" off"}${sel===d.key?" sel":""}" data-k="${esc(d.key)}">
    <span class="g">${ICON[d.type]||ICON.unknown}</span><span class="n">${esc(nameOf(d))}</span>${TRUST[d.trust]?`<span class="g tb" title="${TRUST[d.trust].label}" style="color:${TRUST[d.trust].c}">${TRUST[d.trust].g}</span>`:""}${worst(d)&&worst(d)!=="info"?`<span class="rdot" title="${esc(worst(d))} risk" style="background:${SEVC[worst(d)]};box-shadow:0 0 6px ${SEVC[worst(d)]}"></span>`:""}<span class="g lk" title="${esc(linkText(d))}">${d.link&&d.link!=="unknown"?LINK[d.link]:""}</span><span class="i">${esc(d.ip)}</span></div>`).join("")
    ||`<div class="empty">No matches</div>`;
  $("list").querySelectorAll(".row").forEach(r=>r.onclick=()=>select(r.dataset.k));
}
const SCORE={high:35,medium:15,low:4,info:0};
const FEEDICON={mDNS:"◉",SSDP:"◎",LLMNR:"?",online:"▲",offline:"▼",port:"⊕",ip:"⇄",security:ALERT,conn:"⇆"};
function sparkline(pts){
  // pts: [[t, rtt|null], ...] — gaps for lost pings, red ticks mark the losses
  const W=360,H=64,P=6; if(!pts.length)return `<svg class="spark" viewBox="0 0 ${W} ${H}"><text x="${W/2}" y="${H/2}" text-anchor="middle">collecting…</text></svg>`;
  const vals=pts.map(p=>p[1]).filter(v=>v!=null), max=Math.max(5,...vals)*1.15;
  const t0=pts[0][0], t1=Math.max(pts[pts.length-1][0],t0+1);
  const X=t=>P+(t-t0)/(t1-t0)*(W-2*P), Y=v=>H-P-(v/max)*(H-2*P);
  let line="",area="",seg=[];const flush=()=>{if(seg.length){line+="M"+seg.join("L");
    area+=`M${seg[0].split(",")[0]},${H-P}L${seg.join("L")}L${seg[seg.length-1].split(",")[0]},${H-P}Z`;seg=[]}};
  let ticks="", grid="";
  for(let i=1;i<4;i++)grid+=`<line class="grid" x1="0" x2="${W}" y1="${H*i/4}" y2="${H*i/4}"/>`;
  for(let i=1;i<12;i++)grid+=`<line class="grid" y1="0" y2="${H}" x1="${W*i/12}" x2="${W*i/12}"/>`;
  pts.forEach(([t,v])=>{if(v==null){flush();ticks+=`<line class="ls" x1="${X(t)}" x2="${X(t)}" y1="${H-P}" y2="${H-P-8}"/>`}else seg.push(`${X(t).toFixed(1)},${Y(v).toFixed(1)}`)});flush();
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${grid}<path class="ar" d="${area}"/><path class="ln" d="${line}"/>${ticks}
    <text x="${W-P}" y="11" text-anchor="end">${Math.round(max)} ms</text></svg>`;
}
function gauge(score,color){
  const c=2*Math.PI*22;
  return `<div class="gauge" title="Risk score from NetMap's findings"><svg viewBox="0 0 54 54"><circle class="bgc" cx="27" cy="27" r="22"/>
    <circle class="fgc" cx="27" cy="27" r="22" stroke="${color}" stroke-dasharray="${c*Math.max(score,2)/100} ${c}" style="filter:drop-shadow(0 0 4px ${color})"/>
    <text class="num" x="27" y="27" fill="${color}">${score}</text></svg>risk</div>`;
}
function findCard(f){return `<div class="find"><span class="sev ${f.severity}">${f.severity}</span><span class="cat ${f.category||""}">${f.category==="suspicious"?"suspicious":"weakness"}</span><b>${esc(f.title)}</b><p>${esc(f.detail)}</p>${f.fix?`<p class="fix">Fix: ${esc(f.fix)}</p>`:""}</div>`}
function renderDetail(){
  const d=S.devices.find(x=>x.key===sel);
  if(!d){$("detail").innerHTML=`<div class="ptitle">Target intel</div><div class="idle">Select a node on the radar to see its live activity, history and security details.</div>`;return}
  if($("detail").contains(document.activeElement)&&document.activeElement.tagName==="INPUT")return;
  const L=LIVE&&LIVE.key===d.key?LIVE:null;
  const ports=d.ports.map(p=>`<span class="chip${p==5555?" warn":""}">${p} ${esc(d.port_names[p]||"")}</span>`).join("")||"none found";
  const svcs=d.services.map(s=>`<span class="chip">${esc(s)}</span>`).join("")||"none";
  const F=d.findings||[], score=Math.min(100,F.reduce((n,f)=>n+(SCORE[f.severity]||0),0));
  const scoreColor=score>=35?SEVC.high:score>=15?SEVC.medium:score>0?SEVC.low:"#2bff9a";
  const fmt=(v,u)=>v==null?"–":v+(u||"");
  // --- activity feed: broadcasts heard + recorded changes + live connections, newest first
  let feed=[];
  if(L){
    L.events.forEach(e=>feed.push({t:e.t,icon:FEEDICON[e.proto]||"•",proto:e.proto,text:e.text+(e.count>1?` ×${e.count}`:""),sev:e.flag||""}));
    L.changes.forEach(c=>feed.push({t:c.t,icon:FEEDICON[c.kind]||"•",proto:"change",text:c.text,sev:c.flagged?c.sev:""}));
    L.connections.forEach(c=>feed.push({t:L.now,icon:FEEDICON.conn,proto:c.proto,text:`connected to this PC: ${c.local} ↔ ${c.peer}${c.process?" ("+c.process+")":""}`,sev:""}));
  }else (d.changes||[]).forEach(c=>feed.push({t:c.t,icon:FEEDICON[c.kind]||"•",proto:"change",text:c.text,sev:c.flagged?c.sev:""}));
  feed.sort((a,b)=>b.t-a.t); feed=feed.slice(0,40);
  const tl=L?L.timeline:[];
  const oldFeed=$("detail").querySelector(".feed"), feedTop=oldFeed?oldFeed.scrollTop:0;
  $("detail").innerHTML=`<div class="ptitle">Target intel</div><div class="body">
   <div class="dhead"><span class="big g">${ICON[d.type]||ICON.unknown}</span><div style="min-width:0"><h2>${esc(nameOf(d))}</h2>
   <div class="tl">${esc(d.kind||d.type_label)}${d.os?" · "+esc(d.os):""} · ${d.online?'<span style="color:var(--ok)">● online</span>':"offline, last seen "+ago(d.last_seen)}${d.new?" · new":""}</div></div>
   ${gauge(score,scoreColor)}</div>

   <div class="sect" style="margin-top:4px"><h3>Live link ${d.online?"· ping 2 s":""}</h3>
   ${d.online?`<div class="kpis">
      <div class="kpi"><div class="v">${fmt(L&&L.rtt_now," ms")}</div><div class="k">latency</div></div>
      <div class="kpi"><div class="v">${fmt(L&&L.rtt_avg," ms")}</div><div class="k">average</div></div>
      <div class="kpi"><div class="v">${fmt(L&&L.jitter," ms")}</div><div class="k">jitter</div></div>
      <div class="kpi"><div class="v" style="color:${L&&L.loss>10?SEVC.high:"inherit"}">${fmt(L&&L.loss,"%")}</div><div class="k">loss</div></div></div>
     ${sparkline(L?L.live:[])}
     <div class="sparkcap"><span>last ${L&&L.live.length?Math.round((L.now-L.live[0][0])/60*10)/10+" min":"–"}</span><span>${L&&L.loss>0?"red ticks = no reply":"phones may skip replies while asleep"}</span></div>`
     :`<p class="sub">Offline. Last seen ${ago(d.last_seen)}.</p>`}</div>

   <div class="sect"><h3>Last 24 hours</h3>
     <div class="kpis">
      <div class="kpi"><div class="v">${fmt(L&&L.uptime_24h,"%")}</div><div class="k">online</div></div>
      <div class="kpi"><div class="v">${fmt(L&&L.drops_24h)}</div><div class="k">drops</div></div>
      <div class="kpi"><div class="v">${d.ports.length}</div><div class="k">ports</div></div>
      <div class="kpi"><div class="v">${(d.changes||[]).length}</div><div class="k">changes</div></div></div>
     <div class="tline">${tl.map(v=>`<span class="${v==null?"":v>=.99?"on":v>0?"part":"off"}" title="${v==null?"no data":Math.round(v*100)+"% online"}"></span>`).join("")||Array(48).fill("<span></span>").join("")}</div>
     <div class="tcap"><span>-24 h</span><span>-12 h</span><span>now</span></div></div>

   <div class="sect"><h3>Threat analysis</h3>${F.length?F.map(f=>`<div class="find"><span class="sev ${f.severity}">${f.severity}</span><span class="cat ${f.category||""}">${f.category==="suspicious"?"suspicious":"weakness"}</span>
     <b>${esc(f.title)}</b><p>${esc(f.detail)}</p>${f.fix?`<p class="fix">Fix: ${esc(f.fix)}</p>`:""}</div>`).join("")
     :`<p class="sub">${d.online?"Nothing harmful or suspicious found by NetMap's checks.":"Device is offline; checks run when it's back."}</p>`}</div>

   <div class="sect"><h3>Deep vulnerability scan</h3>
     ${d.online?`<button class="deepbtn" id="deepbtn"${deepBusy===d.key?" disabled":""}>${deepBusy===d.key?"Scanning…":(d.deep?"Run again":"Run deep scan")}</button>`:`<p class="sub">Device is offline — the deep scan runs when it's back online.</p>`}
     ${deepBusy===d.key?`<p class="sub">Scanning ${esc(d.ip)} across a wide range of common ports and matching open services against known weaknesses… this can take 15–30 seconds.</p>`
       :d.deep?`<p class="sub">Scanned ${d.deep.scanned} ports · ${d.deep.open.length} open · ${ago(d.deep.ts)}${d.deep.new_ports.length?` · <b style="color:var(--warn)">${d.deep.new_ports.length} beyond the quick scan</b>`:""}</p>
         ${d.deep.new_ports.length?`<div class="newp">${d.deep.new_ports.map(p=>`<span class="pt">${p}</span>`).join("")}</div>`:""}
         ${d.deep.vulns.length?d.deep.vulns.map(findCard).join(""):`<p class="sub">No known vulnerabilities matched on the open ports.</p>`}`
       :(d.online?`<p class="sub">Checks a wide range of common ports (far more than the quick scan) and matches what's listening against known weaknesses. Only this device is scanned, entirely offline — no data leaves your network.</p>`:"")}</div>

   <div class="sect"><h3>Live activity</h3>${feed.length?`<div class="feed">${feed.map(e=>`<div class="ev ${e.sev}"><span class="g">${e.icon}</span>
     <span><span class="p">${esc(e.proto)}</span>${esc(e.text)}</span><span class="w">${ago(e.t)}</span></div>`).join("")}</div>`
     :`<p class="sub">${L?"Nothing heard from this device yet. Broadcasts, connections and changes appear here as they happen.":"Loading…"}</p>`}</div>

   <div class="sect"><h3>Services</h3>${(d.svc_detail||[]).length?d.svc_detail.map(v=>`<div class="svc"><span class="pt">${v.port}</span><span>${esc(v.name||"unknown")}</span>${v.banner?`<span class="bn">${esc(v.banner)}</span>`:""}</div>`).join("")
     :`<p class="sub">${ports==="none found"?"No open ports found (common for phones).":ports}</p>`}</div>

   <div class="sect"><h3>Identity</h3><dl>
   <dt>IP address</dt><dd class="mono">${esc(d.ip)}</dd>
   <dt>MAC</dt><dd class="mono">${esc(d.mac||"unknown")}</dd>
   <dt>Vendor</dt><dd>${esc(d.vendor||"unknown")}</dd>
   ${d.model?`<dt>Model</dt><dd>${esc(d.model)}</dd>`:""}
   ${d.os?`<dt>System</dt><dd>${esc(d.os)}${d.ttl?` <span class="sub">(TTL ${d.ttl})</span>`:""}</dd>`:""}
   ${d.hostname||d.rdns?`<dt>Hostname</dt><dd class="mono">${esc(d.hostname||d.rdns)}</dd>`:""}
   ${d.router_name?`<dt>Router calls it</dt><dd>${esc(d.router_name)}</dd>`:""}
   ${linkText(d)?`<dt>Connected</dt><dd>${d.link&&d.link!=="unknown"?`<span class="g">${LINK[d.link]}</span> `:""}${esc(linkText(d))}</dd>`:""}
   ${(S.devices.filter(x=>x.parent===d.key).length)?`<dt>Clients</dt><dd>${S.devices.filter(x=>x.parent===d.key).map(x=>`<span class="chip">${x.link&&x.link!=="unknown"?`<span class="g">${LINK[x.link]}</span> `:""}${esc(nameOf(x))}</span>`).join("")}</dd>`:""}
   ${d.bridge_info&&d.bridge_info.model?`<dt>Hardware</dt><dd>${esc(d.bridge_info.model)} · ${esc(d.bridge_info.firmware)}${d.bridge_info.uptime?" · up "+esc(d.bridge_info.uptime):""}</dd>`:""}
   ${d.alias?`<dt>Detected as</dt><dd>${esc(d.name)}</dd>`:""}
   <dt>Announces</dt><dd>${svcs}</dd>
   <dt>First seen</dt><dd>${ago(d.first_seen)}</dd></dl></div>
   <div class="sect"><h3>Trust</h3><div class="trustseg" id="trustseg">
     <button data-s="trusted" class="${d.trust==="trusted"?"on":""}"><span class="g">${SHIELD}</span> Trusted</button>
     <button data-s="guest" class="${d.trust==="guest"?"on":""}"><span class="g">${TRUST.guest.g}</span> Guest</button>
     <button data-s="" class="${d.trust?"":"on"}"><span class="g">${QUESTION}</span> Unknown</button></div>
     <p class="sub" style="margin:6px 2px 0">${d.trust==="trusted"?"Known device. Won't be flagged as unidentified.":d.trust==="guest"?"Someone's guest — expected, but not yours.":"Not yet reviewed. Unknown devices with no name are flagged."}</p></div>
   <div class="rename"><input id="alias" placeholder="Give it your own name" value="${esc(d.alias)}"><button id="savealias">Save</button></div></div>`;
  $("trustseg").querySelectorAll("button").forEach(b=>b.onclick=async()=>{
    await fetch("/api/trust",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({key:d.key,status:b.dataset.s})});load();pollLive()});
  $("savealias").onclick=async()=>{await fetch("/api/alias",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({key:d.key,name:$("alias").value})});$("alias").blur();load()};
  $("alias").onkeydown=e=>{if(e.key==="Enter")$("savealias").click()};
  const db=$("deepbtn"); if(db)db.onclick=async()=>{
    deepBusy=d.key; renderDetail();
    try{await fetch("/api/deepscan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:d.key})})}catch(e){}
    deepBusy=null; await load(); pollLive();
  };
  const nf=$("detail").querySelector(".feed"); if(nf)nf.scrollTop=feedTop;
}
$("fkind").onchange=e=>{fkind=e.target.value;try{localStorage.setItem("netmap.kind",fkind)}catch(_){};render()};
$("fos").onchange=e=>{fos=e.target.value;try{localStorage.setItem("netmap.os",fos)}catch(_){};render()};
document.querySelectorAll("#seg button").forEach(b=>b.onclick=()=>{view=b.dataset.f;
  try{localStorage.setItem("netmap.view",view)}catch(e){};render()});
$("bell").onclick=async()=>{showAlerts=!showAlerts;render();
  if(showAlerts&&S.unseen){await fetch("/api/alerts/seen",{method:"POST"});load()}};
$("scanbtn").onclick=async()=>{await fetch("/api/scan",{method:"POST"});load()};
$("filter").oninput=e=>{filterText=e.target.value;renderList()};
addEventListener("resize",()=>S&&renderMap());
// Topology zoom & pan
(function(){
  const wrap=$("mapwrap"), svg=$("map");
  $("zoomctl").querySelectorAll("button").forEach(b=>b.onclick=()=>{
    const z=b.dataset.z; if(z==="in")zoomBy(1.4); else if(z==="out")zoomBy(1/1.4); else resetView();});
  wrap.addEventListener("wheel",e=>{if(svg.hidden)return;e.preventDefault();zoomBy(e.deltaY<0?1.18:1/1.18,e.clientX,e.clientY)},{passive:false});
  let sx=0,sy=0,scx=0,scy=0,down=false;
  svg.addEventListener("pointerdown",e=>{if(vz<=1||e.button!==0)return;down=true;didDrag=false;sx=e.clientX;sy=e.clientY;scx=vcx;scy=vcy;svg.classList.add("grabbing");try{svg.setPointerCapture(e.pointerId)}catch(_){}});
  svg.addEventListener("pointermove",e=>{if(!down)return;const r=svg.getBoundingClientRect(),w=baseW/vz,h=baseH/vz;
    if(Math.abs(e.clientX-sx)+Math.abs(e.clientY-sy)>4)didDrag=true;
    vcx=scx-(e.clientX-sx)/r.width*w; vcy=scy-(e.clientY-sy)/r.height*h; clampView(); applyView()});
  const end=()=>{if(down){down=false;svg.classList.remove("grabbing");setTimeout(()=>didDrag=false,30)}};
  svg.addEventListener("pointerup",end); svg.addEventListener("pointercancel",end);
})();
const tick=()=>$("clock").textContent=new Date().toLocaleTimeString([], {hour12:false});tick();setInterval(tick,1000);
if(location.hash.startsWith("#dev="))sel=decodeURIComponent(location.hash.slice(5));
load().then(pollLive);setInterval(load,4000);setInterval(pollLive,2000);
</script></body></html>"""


def main():
    load()
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=passive_listener, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"NetMap running at {url}  (Ctrl+C to stop)")
    if "--no-open" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
