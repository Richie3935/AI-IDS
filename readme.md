# AI-Powered Intrusion Detection System (IDS) - Version 3

A modular Python IDS built with Scapy. Version 3 includes live packet
capture, real-time traffic statistics, and a rule-based detection engine
for common reconnaissance and flood patterns.

## Project Structure

```text
AI_IDS/
|
├── main.py
├── packet_capture.py
├── traffic_stats.py
├── detection/
│   ├── __init__.py
│   ├── config.py
│   └── rule_engine.py
├── requirements.txt
└── README.md
```

## Features

- Packet sniffer using Scapy
- Real-time traffic statistics with thread-safe counters
- Rule-based detection engine
- Port scan detection
- TCP SYN flood detection
- ICMP flood detection
- Console alerts with timestamp, source IP, attack type, severity, and details
- Configurable thresholds in `detection/config.py`
- CLI overrides for common detection thresholds
- Logging and exception handling around packet capture, callbacks, and rules

## Detection Logic

### Port Scan Detection

The rule engine tracks destination ports contacted by each source IP in a
sliding time window. If a source contacts at least
`port_scan_unique_ports` unique destination ports within
`port_scan_window_seconds`, an alert is generated.

Default: 10 unique destination ports in 60 seconds.

### SYN Flood Detection

The engine monitors TCP packets with SYN set and ACK not set. For each
source IP, it counts SYN packets in a sliding time window. If the count
meets or exceeds `syn_flood_packet_threshold`, an alert is generated.

Default: 100 SYN packets in 10 seconds.

### ICMP Flood Detection

The engine tracks ICMP packets per source IP in a sliding time window. If
the count meets or exceeds `icmp_flood_packet_threshold`, an alert is
generated.

Default: 50 ICMP packets in 10 seconds.

### Alert Cooldowns

Each attack type/source IP pair has a cooldown to avoid printing the same
alert continuously during a sustained attack. Cooldowns are configured in
`detection/config.py`.

## Requirements

- Python 3.11+
- Scapy 2.5.0+
- Administrator/root privileges for live packet capture

Install dependencies:

```bash
pip install -r requirements.txt
```

On Windows, install Npcap from [https://npcap.com/](https://npcap.com/)
and run the terminal as Administrator.

## Usage

Basic capture:

```bash
python main.py
```

Capture on a specific interface:

```bash
python main.py -i eth0
```

Capture only TCP traffic:

```bash
python main.py -f "tcp"
```

Stop after 500 packets:

```bash
python main.py -c 500
```

Disable per-packet display while keeping stats and alerts:

```bash
python main.py --no-display
```

Write logs to a file:

```bash
python main.py --log-level INFO --log-file ids.log
```

Tune rule thresholds for one run:

```bash
python main.py --port-scan-window 30 --port-scan-ports 8
python main.py --syn-window 5 --syn-threshold 50
python main.py --icmp-window 5 --icmp-threshold 25
```

Disable rule alerts:

```bash
python main.py --disable-rules
```

## Alert Format

```text
[ALERT] 2026-06-23 18:30:00 | Source=192.168.1.50 | Type=Port Scan | Severity=HIGH | 10 unique destination ports contacted within 60s
```

Each alert includes:

- Timestamp
- Source IP
- Attack type
- Severity
- Detection details

## Configuration

Thresholds live in `detection/config.py`:

```python
DetectionConfig(
    port_scan_window_seconds=60,
    port_scan_unique_ports=10,
    syn_flood_window_seconds=10,
    syn_flood_packet_threshold=100,
    icmp_flood_window_seconds=10,
    icmp_flood_packet_threshold=50,
)
```

Use conservative defaults in production and tune thresholds to match
normal traffic patterns in your environment. Very low thresholds can
produce false positives on busy networks.

## Cybersecurity Notes

- Run packet capture only on networks and systems where you have explicit
  authorization.
- Prefer least privilege and use elevated permissions only for capture.
- Keep logs protected because they can contain sensitive IP metadata.
- Treat this rule engine as a baseline detection layer, not a replacement
  for full enterprise monitoring.

## Architecture

`PacketCapture` parses Scapy packets into immutable `PacketInfo` objects.
`TrafficStats` updates counters for every packet. `RuleEngine` is
registered as a packet callback and evaluates each packet independently
using thread-safe sliding windows.

This keeps capture, statistics, and detection modular, so future database,
dashboard, or ML modules can attach through the same callback pattern.
