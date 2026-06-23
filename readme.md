# AI-Powered Intrusion Detection System (IDS)

A modular, production-quality foundation for a **Hybrid AI-Powered IDS**
built with Python 3.11+ and Scapy.  Version 1 implements live packet
capture and real-time traffic statistics — the ingestion and observation
layer on which all future AI/ML detection modules will be built.

---

## Architecture

```
AI_IDS/
│
├── main.py            ← Entry point, CLI, AIIDS application class
├── packet_capture.py  ← PacketCapture engine (Scapy wrapper)
├── traffic_stats.py   ← TrafficStats module (counters + reporting)
├── requirements.txt   ← Python dependencies
└── README.md          ← This file
```

### Module interaction

```
┌──────────────────────────────────────────────────────────┐
│                         main.py                          │
│  ┌─────────────────────┐   ┌──────────────────────────┐  │
│  │   PacketCapture     │──▶│      TrafficStats        │  │
│  │  (packet_capture.py)│   │   (traffic_stats.py)     │  │
│  └─────────────────────┘   └──────────────────────────┘  │
│         │                                                 │
│         ▼  (future extension points)                      │
│  ┌─────────────────────────────────────────────────┐     │
│  │  Rule Engine │ MySQL Logger │ Flask Dashboard    │     │
│  │  Flow Gen    │ ML Classifier                     │     │
│  └─────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────┘
```

---

## Features

### Packet Capture Module (`packet_capture.py`)
- Live network packet capture via Scapy's `sniff(store=False)`
- Extracts: Source IP, Destination IP, Protocol (TCP/UDP/ICMP), Packet Length, Ports, TCP Flags, TTL
- Clean fixed-width per-packet console output with colour-coded protocol labels
- Graceful handling of malformed / non-IP frames
- `_on_packet()` hook and `register_callback()` for attaching future modules
- Frozen `PacketInfo` dataclass — thread-safe, JSON-serialisable

### Traffic Statistics Module (`traffic_stats.py`)
- Thread-safe real-time counters using `threading.Lock`
- Tracks: Total / TCP / UDP / ICMP / Other packets, Total bytes
- Per-IP top-talker tracking (bounded by `top_n` to prevent memory growth)
- Formatted statistics table printed every N seconds (configurable)
- `get_snapshot()` returns an immutable `TrafficCounters` dataclass
- `_on_report()` hook for pushing stats to DB, dashboard, or ML pipeline
- Context-manager support (`with TrafficStats() as stats:`)

---

## Requirements

| Requirement | Minimum version |
|-------------|----------------|
| Python      | 3.11            |
| Scapy       | 2.5.0           |

### System dependencies

**Linux (Debian/Ubuntu)**
```bash
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev python3-pip
```

**Linux (Fedora/RHEL)**
```bash
sudo dnf install python3-devel libpcap-devel python3-pip
```

**macOS**
```bash
# libpcap ships with Xcode Command Line Tools; install if missing:
xcode-select --install
# or via Homebrew:
brew install libpcap
```

**Windows**
1. Download and install [Npcap](https://npcap.com/) — choose "WinPcap API-compatible mode".
2. Run all commands in an Administrator PowerShell or CMD window.

---

## Installation

### 1. Clone / download the project
```bash
git clone https://github.com/your-org/AI_IDS.git
cd AI_IDS
```

### 2. Create and activate a virtual environment (recommended)
```bash
python3 -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

### 3. Install Python dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

> **Important:** Raw packet capture requires elevated privileges.

### Basic capture (default interface, all traffic)
```bash
sudo python main.py
```

### Capture on a specific interface
```bash
sudo python main.py -i eth0
sudo python main.py -i en0      # macOS
```

### Apply a BPF capture filter
```bash
sudo python main.py -i eth0 -f "tcp"
sudo python main.py -i eth0 -f "tcp port 80 or tcp port 443"
sudo python main.py -i eth0 -f "not arp"
```

### Stop after N packets
```bash
sudo python main.py -i eth0 -c 500
```

### Change the statistics report interval
```bash
sudo python main.py --interval 30
```

### Suppress per-packet output (stats-only mode)
```bash
sudo python main.py --no-display
```

### Enable debug logging and write to a log file
```bash
sudo python main.py --log-level DEBUG --log-file ids.log
```

### Full CLI reference
```
usage: AI-IDS [-h] [-i IFACE] [-f BPF] [-c N] [--no-display]
              [--interval SEC] [--top-n N]
              [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
              [--log-file PATH]

Capture options:
  -i, --interface IFACE   Network interface (default: system default)
  -f, --filter BPF        BPF filter string
  -c, --count N           Stop after N packets (0 = unlimited)
  --no-display            Suppress per-packet output

Statistics options:
  --interval SEC          Stats report interval in seconds (default: 10)
  --top-n N               Number of top-talker IPs to show (default: 5)

Logging options:
  --log-level LEVEL       DEBUG | INFO | WARNING | ERROR | CRITICAL
  --log-file PATH         Write logs to file
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════╗
║          AI-Powered Intrusion Detection System           ║
║                       v1.0.0                            ║
╠══════════════════════════════════════════════════════════╣
║  Interface  : eth0                                      ║
║  BPF Filter : none (capture all)                        ║
║  Pkt Limit  : unlimited                                 ║
║  Stats Every: 10s                                       ║
╚══════════════════════════════════════════════════════════╝

[*] Capturing packets on eth0 — Ctrl+C to stop

TIME         SRC IP             DST IP             PROTO    LEN   SPORT   DPORT  FLAGS
────────────────────────────────────────────────────────────────────────────────
12:00:01.234 192.168.1.10       142.250.80.78      TCP      74B      52432     443  A
12:00:01.235 142.250.80.78      192.168.1.10       TCP      66B        443   52432  A
12:00:01.240 192.168.1.10       8.8.8.8            UDP      73B      49152      53  —
12:00:01.241 8.8.8.8            192.168.1.10       UDP      89B         53   49152  —
12:00:01.510 192.168.1.1        192.168.1.10       ICMP     84B          —       —  —

╔══════════════════════════════════════════════════════════╗
║          REAL-TIME TRAFFIC STATISTICS                    ║
║  Snapshot: 2025-09-01 12:00:11                          ║
╠══════════════════════════════════════════════════════════╣
║  Total Packets  : 142                                   ║
║  Total Bytes    : 89.4 KB                               ║
╠══════════════════════════════════════════════════════════╣
║  TCP   Packets  :     98 ( 69.0%)                       ║
║  UDP   Packets  :     31 ( 21.8%)                       ║
║  ICMP  Packets  :      8 (  5.6%)                       ║
║  Other Packets  :      5 (  3.5%)                       ║
╠══════════════════════════════════════════════════════════╣
║  Top Source IPs:                                        ║
║    192.168.1.10           87 pkts                       ║
║    142.250.80.78          34 pkts                       ║
║    8.8.8.8                21 pkts                       ║
╚══════════════════════════════════════════════════════════╝
```

---

## Extension Guide

The codebase is designed as a platform.  Each future module plugs in
without modifying the core capture / stats files.

### Adding a Rule-Based Detection Engine
```python
# rules.py
from packet_capture import PacketCapture, PacketInfo

def port_scan_rule(info: PacketInfo) -> None:
    if info.protocol == "TCP" and info.flags == "S":
        print(f"[ALERT] SYN packet from {info.src_ip} → {info.dport}")

# main.py — register after creating PacketCapture
capture.register_callback(port_scan_rule)
```

### Adding a MySQL Logger
```python
# db_logger.py — subclass TrafficStats and override _on_report()
class DBTrafficStats(TrafficStats):
    def _on_report(self, snapshot):
        db.insert(snapshot.as_dict())
```

### Adding a Flask Dashboard
Mount a Flask app in a separate thread; expose a `/stats` endpoint that
calls `stats.get_snapshot()` and returns `jsonify(snapshot.as_dict())`.
For live updates use Flask-SocketIO and emit from `_on_report()`.

### Adding ML Detection
```python
# ml_detector.py
from packet_capture import PacketInfo

class MLDetector:
    def __call__(self, info: PacketInfo) -> None:
        features = extract_features(info)
        label    = self.model.predict([features])[0]
        if label == 1:
            print(f"[ML ALERT] Anomaly detected: {info.src_ip}")

capture.register_callback(MLDetector())
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| `store=False` in Scapy sniff | Prevents packet buffer from growing unbounded |
| `frozen=True` on `PacketInfo` | Thread-safe sharing; prevents accidental mutation |
| `threading.Lock` in TrafficStats | Sniffer and timer run on separate threads |
| Daemon threads for the timer | JVM-style: timer won't block interpreter exit |
| `defaultdict(int)` for IP tallies | O(1) increment, no KeyError on first occurrence |
| Bounded `top_n` for IP tracking | Prevents memory growth in long-running sessions |
| Hook methods vs inheritance | Allows composition without modifying core classes |

---

## Roadmap

- [x] **v1.0** — Packet Capture + Traffic Statistics (this release)
- [ ] **v1.1** — Rule-Based Detection Engine (threshold / signature rules)
- [ ] **v1.2** — MySQL / SQLite Logging
- [ ] **v1.3** — Flask Real-Time Dashboard (Chart.js + SSE)
- [ ] **v1.4** — NetFlow / IPFIX Flow Generation
- [ ] **v2.0** — ML-Based Anomaly Detection (Isolation Forest / LSTM)

---

## License

MIT — see `LICENSE` for details.