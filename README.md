# NetMap

A live, self-hosted map of every device on your local network — a single-file
Python app with a futuristic radar console in your browser. No agents, no cloud,
no accounts. It only uses what your machine already has, and the web UI is served
on **localhost only**.

> _Tip: add a screenshot at `docs/screenshot.png` and reference it here — use a
> network with no personal device names if the repo is public._

## Features

- **Live radar topology** — every device as a node on a hub-and-spoke map, with
  device-type icons, Wi-Fi/wired link badges, and risk highlights that update as
  the network changes.
- **Zoom & pan** — mouse-wheel zoom-to-cursor, zoom buttons, and drag-to-pan.
- **Drill into a node** — double-click a hub (router, Wi-Fi bridge, switch) to
  focus its sub-topology, with a breadcrumb to climb back out.
- **Per-device deep scan** — on-demand audit that scans ~200 common TCP ports,
  fingerprints what's listening, and matches it against known weaknesses
  (backdoor ports, exposed RDP/Docker/Memcached/Elasticsearch, Telnet/FTP, open
  VNC, outdated firmware, large attack surface, and more). **Fully offline** — no
  external CVE lookups, no exploitation.
- **Passive activity feed** — listens for mDNS/SSDP so you see what devices
  announce and when they join.
- **Security findings** — plain-language weaknesses with concrete fixes.
- **Trust labels** — mark devices as trusted / guest so unknowns stand out.
- **Rename devices**, latency/uptime history, and new-device alerts.

## Requirements

- **Linux** with **Python 3.8+** (standard library only — no `pip install`).
- Optional but recommended: **`avahi-browse`** (from `avahi`/`avahi-utils`) for
  richer mDNS names.
- Run as a normal user; a ping sweep and TCP connect-probe of your own LAN need
  no root.

## Run

```bash
python3 netmap.py            # opens http://127.0.0.1:8765 in your browser
python3 netmap.py --no-open  # just serve; don't open a browser
```

Then visit **http://127.0.0.1:8765**. The first scan takes ~20 seconds.

## How it works

Discovery uses only local facilities:

- a **ping sweep** of your subnet,
- the kernel **ARP / neighbour table** for MAC addresses and vendors,
- **mDNS** (via `avahi-browse`) and **reverse DNS** for names,
- a short **TCP port probe** + light banner read for service fingerprinting,
- a passive **mDNS/SSDP** listener for the live activity feed.

Everything runs on your machine. Device data is stored locally in
`~/.local/share/netmap/` and is **never** sent anywhere.

## Privacy

NetMap is designed to stay on your network: the UI binds to `127.0.0.1`, there
are no external calls, and the deep scan's vulnerability matching is entirely
offline. Your device inventory never leaves your computer.

## License

[MIT](LICENSE)
