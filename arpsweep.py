#!/usr/bin/env python3

"""
Functionality:
  - ARP sweep of a subnet
"""

from __future__ import annotations

__author__    = "Mikko Tanner"
__copyright__ = f"(c) {__author__} 2025"
__version__   = "0.3.1-1_20250606"
__license__   = "GPL-3.0-or-later"

import asyncio
import json
import os
import sys
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network
from time import sleep
from typing import Any, Callable, Dict, Iterable, List, NoReturn, Optional

from scapy.all import sendp, srp
from scapy.layers.l2 import ARP, Ether

# Are we running in a terminal?
HAVE_TTY = sys.stdout.isatty()
# Ethernet broadcast address
ETHER_BC = Ether(dst="ff:ff:ff:ff:ff:ff")


def parse_cmdline_args():
    """Parse command-line arguments."""

    args = ArgumentParser(description='ARP sweep of a subnet')
    args.add_argument('net', help='IPv4 network (CIDR) to scan')
    args.add_argument('--iface', '-I', help='Interface to use (def: autoselect)')
    args.add_argument('--src', '-S', help='Source IP to use (def: autoselect)')
    args.add_argument('--count', type=int, default=1, help='Number of ARP reqs (def: 1)')
    args.add_argument('--timeout', type=float, default=0.1, help='Req timeout in secs (def: 0.1)')
    args.add_argument('--tasks', '-T', type=int, default=16, help='Scan parallelism (def: 16)')
    args.add_argument('--rand', action='store_true', help='Sweep hosts in random order')
    args.add_argument('--daemon', '-D', action='store_true', help='Detach process (daemonize)')
    args.add_argument('--json', action='store_true', help='JSON output')
    args.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args.add_argument('--debug', action='store_true', help='Debug mode - extra verbose')
    args.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    p = args.parse_args()

    p.net = IPv4Network(p.net)
    p.src = IPv4Address(p.src) if p.src else None

    # be sensible with the number of parallel tasks
    if p.tasks < 1:
        p.tasks = 1
    elif p.tasks > 1:
        p.tasks = min(p.tasks, p.net.num_addresses)

    if p.debug:
        p.verbose = True

    return p


class AsyncARPScanner:
    def __init__(self, args, hosts: Iterable[IPv4Address], callback: Optional[Callable] = None):
        self.exec = ThreadPoolExecutor(thread_name_prefix='arp-sweep')
        self.limiter = asyncio.Semaphore(args.tasks)
        self.timeout = float(args.timeout)
        self.iface: Optional[str] = args.iface
        self.src: Optional[IPv4Address] = args.src
        self.hosts = hosts
        self.count: int = args.count
        self.debug: bool = args.debug
        self.verbose: bool = args.verbose
        self.callback = callback
        # needs no locking, since we are in a single-threaded event loop
        self.responses: Dict[str, Optional[List[Dict]]] = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.exec.shutdown(wait=True)

    async def _send_arp_async(self, host: IPv4Address):
        """Send ARP request asynchronously using thread pool."""
        try:
            loop = asyncio.get_running_loop()
            pkts = create_arp_packets(host, num=self.count, src=self.src)
            args = (pkts, self.timeout, self.iface, self.verbose)
            async with self.limiter:
                # return the host too, so we can easily track who this task is for
                return await loop.run_in_executor(self.exec, send_packets, *args), host
        except Exception as e:  # pylint: disable=broad-except
            if self.debug:
                eprint(f"ERROR: Failed to scan {host}: {e}")
            return None, host

    async def scan_subnet(self):
        """Scan entire subnet asynchronously."""
        tasks = []
        for host in self.hosts:
            tasks.append(self._send_arp_async(host))

        # Gather results
        for i, task in enumerate(asyncio.as_completed(tasks)):
            result, host = await task
            if result:
                self.responses[host] = result
            else:
                self.responses[host] = None

            if self.debug:
                debug_response(host, num=self.count, resp=result)

            # Optional: progress callback
            if self.callback:
                self.callback(host, i + 1, len(self.hosts))

        return self.responses


def eprint(*values, **kwargs):
    """Mimic print() but write to stderr."""
    print(*values, file=sys.stderr, **kwargs)


def debug_response(host: IPv4Address, num: int, resp: Optional[List[Dict]]):
    """Print debug information about each host."""
    if resp:
        srcip = resp[0]['dst_ip']
        eprint(f'DEBUG: sent {num} ARP packets to {host} (src: {srcip}),',
                       f'received {len(resp)} responses')
    else:
        eprint(f'DEBUG: no responses received for {host}')


def simple_tabulate(data: Iterable[Iterable], headers: List = None, missing = '-'):
    """
    Format a list of iterables as a table for printing.

    Args:
        data: List of iterables (lists, tuples) containing the data to display
        headers: Optional list of column headers
        missing: String to replace None values with

    Returns:
        String containing the formatted table
    """
    def format_row(row: tuple[str], widths: List[int]):
        """Format a single row (with padding if needed)."""
        items = [item.ljust(widths[i]) for i, item in enumerate(row)]
        diff = len(widths) - len(items)
        if diff > 0:
            # pad with `missing` value(s) if the row is too short
            items.extend([missing.ljust(widths[i+len(items)]) for i in range(diff)])
        return ' | '.join(items)

    all_rows: List[tuple[str]] = []
    if headers:
        all_rows.append(tuple(str(h) for h in headers))
    for row in data:
        all_rows.append(tuple(str(item) if item is not None else missing for item in row))
    if not all_rows:
        return ''

    # Find the maximum width needed for each column
    columns = 1
    for row in all_rows:
        columns = max(len(row), columns)
    widths = [0] * columns
    for row in all_rows:
        for i, item in enumerate(row):
            widths[i] = max(widths[i], len(item))

    # Format each row with appropriate padding
    formatted_rows: List[str] = []
    if headers:
        # Format headers with a separator line if headers are provided
        formatted_rows.append(format_row(all_rows[0], widths))
        separator = '-+-'.join('-' * w for w in widths)
        formatted_rows.append(separator)

    for row in all_rows[1:] if headers else all_rows:
        formatted_rows.append(format_row(row, widths))

    return '\n'.join(formatted_rows)


def send_packets(pkts: Any, timeout: int, iface: str = None, verbose = False):
    """
    Send packet(s) and return the received response(s).

    Args:
        pkts: The packet(s) to send (e.g., ARP request)
        timeout: Timeout in seconds for waiting for responses
        iface: Network interface to use for sending the packet
        verbose: Whether to print each response to stderr

    Returns:
        List of dictionaries containing the received packets' information
    """
    responses: List[Dict[str, Any]] = []
    ans, unans = srp(pkts, timeout=timeout, iface=iface, verbose=False)
    for sent, resp in ans:
        responses.append({
            # since these are responses, the 'src' and 'dst' are reversed
            'src_ip': resp.psrc,
            'src_hw': resp.hwsrc,
            'dst_ip': resp.pdst,
            'dst_hw': resp.hwdst,
            'type': resp.type,
            'len': len(resp),
            'time': resp.time - sent.sent_time
        })

    if verbose and responses:
        r = responses[0]
        eprint(f"{r['src_ip']} is-at {r['src_hw']} (resp type={r['type']}, len={r['len']})")

    return responses


def create_arp_packets(host: IPv4Address, num: int, src: IPv4Address | None):
    """Create ARP request packet(s) for a given host."""
    return [ETHER_BC / ARP(pdst=str(host), hwsrc=str(src) if src else None) for _ in range(num)]


def do_arp_sweep(hosts: Iterable[IPv4Address], args):
    """Perform an ARP sweep on the specified hosts."""
    responses: Dict[str, Optional[List[Dict]]] = {}

    for host in hosts:
        pkts = create_arp_packets(host, num=args.count, src=args.src)
        resp = send_packets(pkts, timeout=args.timeout, iface=args.iface, verbose=args.verbose)
        if resp:
            responses[host] = resp
        else:
            responses[host] = None

        if args.debug:
            debug_response(host, num=len(pkts), resp=resp)

    return responses


def fork_off():
    """Fork and detach the child process from the terminal/caller."""
    pid = os.fork()
    if pid > 0:
        # exit parent process with success
        sys.exit(0)

    # detach from terminal
    os.setsid()

    # redirect standard file descriptors to /dev/null
    sys.stdin.close()
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, 'rb', 0) as devnull:
        os.dup2(devnull.fileno(), 0)
    with open(os.devnull, 'ab', 0) as devnull:
        os.dup2(devnull.fileno(), 1)
        os.dup2(devnull.fileno(), 2)


def batch_send(args, packets: List[Ether]):
    """Send ARP packets in batches without waiting for responses."""
    for i in range(0, len(packets), args.tasks):
        chunk = packets[i:i+args.tasks]
        sendp(chunk, iface=args.iface, count=args.count, verbose=False, inter=0.05) # 20 pps
        sleep(args.timeout)  # wait a bit before sending the next batch


def daemonize(args, hosts: Iterable[IPv4Address]) -> NoReturn:
    """Daemonize the process to run in the background."""
    pkts = [pkt for h in hosts for pkt in create_arp_packets(h, num=1, src=args.src)]
    fork_off()
    batch_send(args, packets=pkts)
    sys.exit(0)


def main():
    """Main function to run the ARP sweep process"""
    if os.geteuid() != 0:
        eprint("ERROR: root privileges are required to send (raw) ARP packets.")
        sys.exit(1)

    args = parse_cmdline_args()
    hosts: Iterable[IPv4Address] = set(args.net.hosts()) if args.rand else list(args.net.hosts())

    if args.daemon:
        daemonize(args, hosts=hosts)

    if args.verbose and HAVE_TTY:
        eprint(f'INFO: scanning {args.net} (net: {args.net.network_address},',
               f'bcast: {args.net.broadcast_address}, hosts: {len(hosts)})')

    if args.tasks > 1:
        if args.debug and HAVE_TTY:
            eprint(f'DEBUG: using {args.tasks} parallel asyncio tasks for scanning')
        with AsyncARPScanner(args, hosts, callback=None) as scanner:
            results = asyncio.run(scanner.scan_subnet())
    else:
        results = do_arp_sweep(hosts=hosts, args=args)

    if args.json:
        # JSON encoder doesn't like IPv4Address objects -> convert to str
        results = {str(host): resp for host, resp in results.items()}
        print(json.dumps(results, indent=2 if HAVE_TTY else None))
    elif any(val is not None for val in results.values()):
        data = []
        headers = ['IP Address', 'MAC Address', 'Recv', 'Time (ms)']
        for host, responses in results.items():
            if responses is not None:
                resp = responses[0]
                data.append([host, resp['src_hw'], len(responses), f"{resp['time']*1e3:.4f}"])
        data.sort(key=lambda x: x[0])
        print(simple_tabulate(data, headers=headers))
    else:
        eprint("INFO: no responses received.")


if __name__ == "__main__":
    main()
