# arpsweep

An asynchronous ARP scanner for host discovery on IPv4 networks.

## Overview

`arpsweep` performs Layer 2 network discovery by sending ARP (Address Resolution Protocol) requests to identify active hosts on a local network segment. It features parallel scanning capabilities, integration with the system's ARP cache, and flexible output formats.

## Features

- **Asynchronous scanning** with configurable task parallelism for fast network sweeps
- **ARP cache integration** to skip already-known hosts and display cached entries
- **Multiple output formats** human-readable tables and JSON
- **Configurable scan parameters** including packet count, timeout, and source IP
- **Interface detection** with automatic local IP exclusion
- **Background operation** with daemon mode (no output at all). Intended for automated tooling.
- **Random scan order** option to avoid sequential scanning patterns

## Requirements

- Python 3.10+
- Root/administrator privileges (required for raw packet operations)
- Required Python packages:
  - `scapy` (for packet crafting and sending)
- Optional Python packages:
  - `pyroute2` or `pyroute2-minimal` (enhanced interface and ARP cache operations)

## Installation

```bash
# Install dependencies...
sudo apt-get install python3-scapy python3-pyroute2-minimal

# ... or with pip
pip install scapy pyroute2

# Clone the repository and install
git clone https://github.com/Ukko-Ylijumala/arpsweep-py
cd arpsweep-py
./build_deb.sh
sudo dpkg -i dist/arpsweep_x.y.z-1_all.deb
```

## Usage

### Basic Usage

```bash
# Scan a single subnet
$ sudo arpsweep.py 192.168.1.0/24

# Scan with specific interface
$ sudo arpsweep.py -I eth0 192.168.1.0/24

# Fast scan with more parallel tasks and neighbour cache usage
$ sudo arpsweep.py -N -T 32 192.168.1.0/24
```

### Command-line Options

```
positional arguments:
  net                   IPv4 network (CIDR) to scan

options:
  --iface IFACE, -I IFACE
                        Interface to use (default: autoselect)
  --src SRC, -S SRC     Source IP to use (default: autoselect)
  --count COUNT         Number of ARP requestss (default: 1)
  --timeout TIMEOUT     Request timeout in secs (default: 0.1)
  --tasks TASKS, -T TASKS
                        Scan parallelism (default: 16)
  --rand                Sweep hosts in random order
  --daemon, -D          Detach process (daemonize)
  --neigh, -N           Utilize information in ARP/neighbor cache
  --json                JSON output
  --verbose, -v         Verbose output
  --debug               Debug mode - extra verbose
  --version             show program's version number and exit
```

### Output Examples

#### Standard Output
```
$ sudo arpsweep.py --count 2 192.168.1.0/29
IP address    | HW address        | iface | Recv | Time (ms)
--------------+-------------------+-------+------+----------
192.168.1.1   | 00:11:22:33:44:55 | eth1  | 1    | 0.5234
192.168.1.3   | aa:bb:cc:dd:ee:ff | eth1  | 2    | 0.8901
```

#### Verbose Output
```
$ sudo arpsweep.py -v 192.168.1.0/29
192.168.1.1 is-at 00:11:22:33:44:55 dev eth1 (cached)
INFO: scanning 192.168.1.0/29 (net: 192.168.1.0, bcast: 192.168.1.7, hosts: 6 of 6)
192.168.1.3 is-at aa:bb:cc:dd:ee:ff dev eth1
IP address    | HW address        | iface | Recv | Time (ms)
--------------+-------------------+-------+------+----------
192.168.1.1   | 00:11:22:33:44:55 | eth1  | -    | -
192.168.1.3   | aa:bb:cc:dd:ee:ff | eth1  | 1    | 0.8901
```

#### JSON Output
```bash
$ sudo arpsweep.py --json 192.168.1.0/29
```
```json
{
  "192.168.1.1": {
    "hw": "00:11:22:33:44:55",
    "iface": "eth1",
    "resp": 1,
    "time": 0.0005234
  },
  "192.168.1.3": {
    "hw": "aa:bb:cc:dd:ee:ff",
    "iface": "eth1",
    "resp": 1,
    "time": 0.0008901
  },
  { ... }
}
```

### Advanced Usage

#### Utilizing ARP Cache Information
```bash
# Skip hosts already in ARP cache and show cached entries
$ sudo arpsweep.py --neigh 192.168.1.0/24
```

#### Reliability Scanning
```bash
# Send 3 ARP requests per host with longer timeout
$ sudo arpsweep.py --count 3 --timeout 0.5 192.168.1.0/24
```

#### Background Scanning
```bash
# Run scan in background (daemon mode)
$ sudo arpsweep.py --daemon 192.168.1.0/24
```

#### Stealth Scanning
```bash
# Random order with specific source IP
$ sudo arpsweep.py --rand -S 192.168.1.100 192.168.1.0/24
```

## Technical Details

### Scanning Methods

The tool uses three scanning approaches based on the `--tasks` parameter, or `--daemon`:

1. **Sequential mode** (`--tasks 1`): Sends ARP requests one at a time
2. **Parallel mode** (default): Uses Python's `asyncio` with a `ThreadPoolExecutor` to send multiple ARP requests concurrently
3. **Daemon mode** intended for automated tooling, f.ex. to keep ARP cache information fresh. In this mode, we just fire off single ARP packets without waiting for responses, with a small delay between packets (0.05 seconds currently, which translates roughly to 20 pps).

### Local IP Exclusion

The scanner automatically excludes the host's own IP addresses from the scan to avoid pointless self-discovery. When a specific interface is selected with `-I`, only that interface's IPs are excluded.

### ARP Cache Integration

When using `--neigh`, the tool:
- Reads the system's ARP/neighbor cache
- Skips scanning for hosts already in the cache
- Includes cached entries in the output (marked as "cached" in verbose mode)
- Filters cache entries to only show those within the target network

### Performance Considerations

- Default parallelism (16 tasks) balances speed and network load
- Timeout of 0.1 seconds is suitable for local networks
- For larger networks, increase `--tasks` for faster scanning
- For unreliable networks or slow hosts, increase `--timeout` and `--count`

## Limitations

- Only supports IPv4 networks
- Requires Layer 2 connectivity (same broadcast domain)
- Requires root privileges for raw socket access

## Security Considerations

- ARP scanning is generally detectable by network monitoring tools
- Some hosts may log ARP scans as suspicious activity
- Use responsibly and only on networks you own or have permission to scan
- The `--daemon` mode detaches from the terminal/caller and continues scanning in the background

## Troubleshooting

### No responses received
- Verify you're scanning the correct network range
- Check if the interface is up and has an IP in the target network
- Try increasing `--timeout` or `--count`
- Some devices may not answer to ARP packets

### Interface warnings
If you see warnings about packet interface mismatches, you may have asymmetric routing or multiple interfaces on the same network. Use `-I` to specify the correct interface.

### Missing pyroute2 features
Install `pyroute2-minimal` for enhanced interface detection and ARP cache reading.

## License

GPL-3.0-or-later

## Author

Mikko Tanner

## NOTE

This README.md has been mostly autogenerated with an AI. There could be slight mistakes.
