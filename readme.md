# AI-Powered Intrusion Detection System (IDS)

A modular Python IDS built with Scapy. The system includes live packet
capture, real-time traffic statistics, rule-based detection, persistent
MySQL alert storage, and a Flask monitoring dashboard.

## Project Structure

```text
AI_IDS/
|
|-- main.py
|-- packet_capture.py
|-- traffic_stats.py
|-- detection/
|   |-- __init__.py
|   |-- config.py
|   `-- rule_engine.py
|-- database/
|   |-- __init__.py
|   |-- mysql_handler.py
|   `-- schema.sql
|-- dashboard/
|   |-- app.py
|   |-- static/
|   `-- templates/
|-- requirements.txt
`-- readme.md
```

## Features

- Live packet capture using Scapy
- Thread-safe traffic statistics
- Rule-based detection for port scans, TCP SYN floods, and ICMP floods
- MySQL alert persistence with connection pooling
- Parameterized SQL queries
- Graceful handling and logging of database failures
- Flask dashboard with Bootstrap UI and Chart.js visualizations
- Searchable alert history with attack type and severity filters

## Requirements

- Python 3.11+
- MySQL Server 8.0+ or compatible MySQL instance
- Administrator/root privileges for live packet capture
- Npcap on Windows: [https://npcap.com/](https://npcap.com/)

Install dependencies:

```bash
pip install -r requirements.txt
```

## MySQL Setup

Create the database and alerts table:

```bash
mysql -u root -p < database/schema.sql
```

Configure the IDS and dashboard with environment variables:

```bash
set AI_IDS_DB_HOST=localhost
set AI_IDS_DB_PORT=3306
set AI_IDS_DB_USER=root
set AI_IDS_DB_PASSWORD=your_password
set AI_IDS_DB_NAME=ai_ids
set AI_IDS_DB_POOL_SIZE=5
```

On Linux/macOS, use `export` instead of `set`.

## Running the IDS

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

## Running the Dashboard

Start the IDS in one terminal, then start the dashboard in another:

```bash
python dashboard/app.py
```

Open:

```text
http://127.0.0.1:5000
```

The IDS writes the latest traffic counters to
`dashboard/static/stats_snapshot.json` by default. To use a different path,
point both processes at the same file:

```bash
python main.py --stats-snapshot-file C:\tmp\ai_ids_stats.json
set AI_IDS_STATS_FILE=C:\tmp\ai_ids_stats.json
python dashboard/app.py
```

## Alert Storage

The `alerts` table stores:

- `id`
- `timestamp`
- `source_ip`
- `destination_ip`
- `attack_type`
- `severity`
- `description`

When the rule engine detects an attack, it emits the existing console/log
alert and then calls `MySQLAlertRepository.insert_alert()`. The repository
uses a MySQL connection pool and parameterized queries. If MySQL is down or
temporarily unreachable, the error is logged and packet capture continues.

## Dashboard Pages

- Home: total packets captured, total alerts, active threats, and latest alerts
- Alerts: full alert history with search, attack type filtering, and severity filtering
- Statistics: attack counts, traffic counters, top talkers, and Chart.js charts

## Architecture

`PacketCapture` parses Scapy packets into immutable `PacketInfo` objects.
`TrafficStats` updates counters for every packet. `RuleEngine` is registered
as a packet callback and evaluates each packet with thread-safe sliding
windows.

The database module is attached to the existing rule-engine alert boundary.
The dashboard reads MySQL alerts and the existing traffic statistics snapshot;
it does not reimplement packet capture, traffic counting, or detection logic.

## Cybersecurity Notes

- Run packet capture only on networks and systems where you have authorization.
- Use least privilege except where elevated capture permissions are required.
- Protect logs and database records because they may contain sensitive IP metadata.
- Treat the rule engine as a baseline detection layer, not a replacement for full enterprise monitoring.
