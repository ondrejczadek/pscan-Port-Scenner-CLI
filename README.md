# pyscan — TCP & UDP Network Scanner (CLI)

**pyscan** is a lightweight command-line network scanner for educational use.  
It performs TCP connect scans and protocol-aware UDP probes (DNS/NTP), supports parallel scanning, and can export results to CSV. Use it to discover open ports and basic service responses on hosts you own or are authorized to test.

> ⚠️ **Use only on networks and hosts you own or have explicit permission to test. Unauthorized scanning may be illegal.**

---

## Features

- TCP connect scan (detect open TCP ports).  
- UDP probes with protocol-aware payloads (DNS, NTP) and basic response verification.  
- Scan by port ranges or lists (e.g. `1-1024,80,443`).  
- CLI flags: `--tcp`, `--udp`, `--threads`, `--timeout`, `--csv`.  
- ThreadPool-based parallel scanning for speed.  
- CSV export of results for reporting.

---

## Prerequisites

- **Python 3.8+** installed and available as `python` in PATH.  
  If `python` is not recognized, install from [python.org](https://www.python.org/) and enable *Add Python to PATH*, or use full path in the `.bat`.

- Recommended Python packages (optional, core script uses only stdlib + `socket`):  
  - `pip install --upgrade pip`

- Notes:  
  - Raw socket features (SYN scans, raw ICMP) are **not** required by default.  
  - Admin/root is required only for raw sockets or packet-capture features if you add them later (ARP scan, raw SYN).

---

## Files

Place these files in the same folder (e.g., `C:\Users\you\tools\pyscan\`):

- `pyscan.py` — the Python scanner script  
- `pyscan.bat` — Windows launcher

**`pyscan.bat` example content:**

```bat
@echo off
set script=%~n0.py
python "%~dp0%script%" %*
```
- `%~dp0` runs the script from the `.bat` folder.
- `%*` forwards all CLI arguments.

---

## Usage / Syntax

`pyscan <target> <ports> [--tcp] [--udp] [--threads N] [--timeout S] [--csv out.csv]`

- `<target>` — IP address or hostname (e.g. `192.168.1.10` or `example.com`).
- `<ports>` — ports list or ranges, e.g. `1-1024`, `22,80,443`, `53,67,123`.
- `--tcp` — scan TCP only.
- `--udp` — scan UDP only.
- If neither `--tcp` nor `--udp` is given, pyscan scans **both** TCP and UDP.
- `--threads N` — max concurrent workers (default: 200).
- `--timeout S` — socket timeout in seconds (default: 1.0).
- `--csv out.csv` — save results to CSV file.

### Examples

Scan TCP and UDP ports 1–200 on `192.168.1.10`:
`pyscan 192.168.1.10 1-200 --threads 200 --timeout 1.0 --csv results.csv`

TCP-only scan of common ports on `example.com`:
`pyscan example.com 22,80,443 --tcp --threads 100`

UDP DNS probe (checks DNS response verification):
`pyscan 8.8.8.8 53 --udp --timeout 2`

---

## How It Works (brief)

- **TCP:** attempts `socket.connect()` to each port. Successful connect = open.
- **UDP:** sends small protocol-aware payloads (e.g., DNS query for port 53, simple NTP request for port 123). If a matching reply is received (DNS transaction ID match for DNS), the port is considered verified open; otherwise replies are reported as unverified. No reply → `open|filtered`.
- Parallelizes probes using `ThreadPoolExecutor` to scan many targets/ports quickly.
- Optionally writes results to CSV for later analysis.

---

## Output / Behavior

- Console prints per-port findings (e.g., `[TCP OPEN] 80`, `[UDP OPEN VERIFIED] 53`).
- CSV format (when `--csv` used): `protocol,port,status,info`.
- UDP results may be `open_verified`, `open_unverified`, `open|filtered`, or `error` depending on payload/response.

---

## Troubleshooting

**'python' is not recognized**
- Add Python to PATH or edit `pyscan.bat` to call the full interpreter path:

`"C:\Path\To\Python\python.exe" "%~dp0pyscan.py" %*`

**DNS/NTP UDP probes return no reply**
- Many hosts or networks drop UDP or block application-layer queries; try increasing `--timeout` or testing against known public services. UDP scan results can be ambiguous (`open|filtered`) if no ICMP unreachable messages are received.

**Cannot resolve hostname**
- Ensure the target hostname resolves via DNS. If not, use an IP address.
    
**Permission errors (raw sockets / ARP)**
- Admin/root privileges are needed only for raw socket or ARP features (not required by default pyscan). Avoid running as Administrator unless necessary.

---

## Optional Enhancements

Ideas you can add later:

- SYN scan via raw sockets (requires admin/root).
- ARP sweep for local network discovery (requires `scapy` and root).
- Additional UDP payloads (SNMP, memcached, etc.).
- Rate limiting, retries, and backoff for noisy networks.
- JSON output, parallel host scanning, and concurrent CSV streaming.

---

## Security & Ethics

- Only scan systems you own or have explicit authorization to test.
- Aggressive scanning may trigger intrusion detection systems or violate acceptable use policies.
- Keep scanning rate moderate on public networks.

---

## Quick Start Checklist

1. Put `pyscan.py` and `pyscan.bat` in the same folder.
2. (Optional) Add that folder to PATH so `pyscan` runs from anywhere.
3. Ensure Python 3.8+ is installed and available as `python`.
4. Open a new CMD/terminal window.
5. Run a simple test against localhost:
	`pyscan 127.0.0.1 22,80 --tcp --threads 50`
6. Inspect console output or use `--csv results.csv` to save results.
