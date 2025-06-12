#!/usr/bin/env python3

"""
Functionality:
  - ARP sweep of a subnet
"""

from __future__ import annotations

__author__    = "Mikko Tanner"
__copyright__ = f"(c) {__author__} 2025"
__version__   = "0.3.2-2_20250612"
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

try:
    from socket import AF_INET
    from pyroute2 import IPRoute
    IPR = IPRoute()
except ImportError:
    IPR = None

# Are we running in a terminal?
HAVE_TTY = sys.stdout.isatty()
# Ethernet broadcast address
ETHER_BC = Ether(dst="ff:ff:ff:ff:ff:ff")
# ARP cache path
ARP_CACHE = '/proc/net/arp'


class Neighbor:
    """Class to represent a neighbor in the ARP cache."""
    def __init__(self, ip: IPv4Address, hw: str, iface: Optional[str] = None,
                 verbose = False, cached = False):
        self.ip = ip
        self.hw = hw
        self.iface = iface
        self.if_ip: Optional[IPv4Address] = None
        self.if_hw: Optional[str] = None
        self.ttl: Optional[int] = None  # time to live (if available)
        self.responses: List[Dict] = []
        self.cached = cached
        if verbose:
            eprint(f'{self}')

    def __repr__(self):
        return f"Neighbor(ip='{self.ip}', mac='{self.hw}', iface='{self.iface}')"

    def __str__(self):
        s = f'{self.ip} is-at {self.hw}'
        if self.iface:
            s += f' dev {self.iface}'
        if self.cached:
            s += ' (cached)'
        return s

    def __len__(self):
        """Number of ARP responses received."""
        return len(self.responses)

    @property
    def time(self):
        """Return the average time of responses."""
        if self.responses:
            return sum(resp['time'] for resp in self.responses) / len(self.responses)
        return 0.0


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
    args.add_argument('--neigh', '-N', action='store_true',
                      help='Utilize information in ARP/neighbor cache')
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

    if p.neigh and IPR is None and p.debug:
        eprint("WARN: --neigh requires 'python3-pyroute2[-minimal]' for some features.")

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
        self.responses: Dict[IPv4Address, Optional[Neighbor]] = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.exec.shutdown(wait=True)

    async def _send_arp_async(self, host: IPv4Address) -> tuple[Optional[Neighbor], IPv4Address]:
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
                debug_response(host, num=self.count, neigh=result)

            # Optional: progress callback
            if self.callback:
                self.callback(host, i + 1, len(self.hosts))

        return self.responses


def eprint(*values, **kwargs):
    """Mimic print() but write to stderr."""
    print(*values, file=sys.stderr, **kwargs)


def debug_response(host: IPv4Address, num: int, neigh: Optional[Neighbor]):
    """Print debug information about each neighbor."""
    if neigh:
        srcip = neigh.if_ip if neigh.if_ip else 'unknown'
        eprint(f'DEBUG: sent {num} ARP packets to {host} (src: {srcip}),',
               f'received {len(neigh)} responses')
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
        Neighbor object with responses, or None if no responses received.
    """
    responses: List[Dict[str, Any]] = []
    ans, unans = srp(pkts, timeout=timeout, iface=iface, verbose=False)
    for sent, resp in ans:
        responses.append({
            # since these are responses, the 'src' and 'dst' are reversed
            'src_ip': resp.psrc,
            'src_hw': resp.hwsrc,
            'type': resp.type,
            'len': len(resp),
            'time': resp.time - sent.sent_time
        })

    if responses:
        r = responses[0]
        neigh = Neighbor(ip=r['src_ip'], hw=r['src_hw'], iface=iface, verbose=verbose)
        neigh.if_ip = IPv4Address(ans[0][1].pdst)
        neigh.if_hw = ans[0][1].hwdst
        neigh.responses = responses
        return neigh

    return None


def create_arp_packets(host: IPv4Address, num: int, src: IPv4Address | None):
    """Create ARP request packet(s) for a given host."""
    return [ETHER_BC / ARP(pdst=str(host), hwsrc=str(src) if src else None) for _ in range(num)]


def do_arp_sweep(hosts: Iterable[IPv4Address], args):
    """Perform an ARP sweep on the specified hosts."""
    responses: Dict[IPv4Address, Optional[Neighbor]] = {}

    for host in hosts:
        pkts = create_arp_packets(host, num=args.count, src=args.src)
        resp = send_packets(pkts, timeout=args.timeout, iface=args.iface, verbose=args.verbose)
        if resp:
            responses[host] = resp
        else:
            responses[host] = None

        if args.debug:
            debug_response(host, num=len(pkts), neigh=resp)

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


def get_interface(iface: str | int) -> Dict:
    """Get interface information using pyroute2 from interface name or index."""
    if isinstance(iface, int):
        link = IPR.get_links(iface)
    else:
        link = IPR.get_links(IPR.link_lookup(ifname=iface)[0])  # pylint: disable=no-member

    if not link or not isinstance(link, list) or len(link) == 0 or not isinstance(link[0], dict):
        raise ValueError(f"interface '{iface}' not found or malformed data ({link=})")

    link  = link[0]  # get the first (and only) link's data
    attrs = {a[0]: a[1] for a in link['attrs']}
    data  = {
        'name': attrs['IFLA_IFNAME'],
        'idx': link['index'],
        'attrs': attrs,
        'hwaddr': attrs.get('IFLA_ADDRESS', 'unknown'),
        'ipaddr': []
        }

    # get IPv4 addresses of the iface - primary addr normally is at index 0
    for ip in IPR.get_addr(index=data['idx'], family=AF_INET):
        addr_attrs = {a[0]: a[1] for a in ip['attrs']}
        data['ipaddr'].append(IPv4Address(addr_attrs['IFA_ADDRESS']))

    return data


def get_arp_cache_fromproc(debug: bool):
    """Get the kernel ARP cache from /proc/net/arp."""
    cache: Dict[IPv4Address, Neighbor] = {}
    if debug:
        eprint(f'DEBUG: Reading ARP cache from {ARP_CACHE}')
    try:
        with open(ARP_CACHE, 'r', encoding='utf-8') as f:
            next(f) # skip header
            for line in f:
                # Fields: IP_addr, HW_type, Flags, HW_addr, Mask, Device
                parts = line.split()
                if len(parts) != 6:
                    if debug:
                        eprint(f"DEBUG: unexpected format in '{ARP_CACHE}': {line.strip()}")
                    break
                try:
                    if parts[2] != '0x0':   # Flag 0x2 = valid entry, 0x0 = incomplete
                        ip, hw, if_name = IPv4Address(parts[0]), parts[3], parts[5]
                        neigh = Neighbor(ip, hw=hw, iface=if_name, verbose=debug, cached=True)
                        if ip not in cache:
                            cache[ip] = neigh
                except (ValueError, IndexError):
                    if debug:
                        eprint(f'DEBUG: could not parse ARP cache entry: {line.strip()}')
    except (FileNotFoundError, PermissionError):
        if debug:
            eprint(f"DEBUG: Could not read ARP cache: '{ARP_CACHE}'")

    return cache


def get_arp_cache(verbose: bool, debug: bool, iface: Optional[str]):
    """Get the kernel ARP cache with pyroute2 (fallback: parse /proc/net/arp)."""
    if IPR is None:
        return get_arp_cache_fromproc(debug)
    if debug:
        eprint('DEBUG: Reading ARP cache using pyroute2')

    if_data = None
    cache: Dict[IPv4Address, Neighbor] = {}

    if iface:
        try:
            if_data = get_interface(iface)
            if debug:
                eprint(f"DEBUG: using interface {if_data['name']} (idx: {if_data['idx']})")
        except (ValueError, IndexError, KeyError) as e:
            eprint(f'ERROR: get_interface: {e}')
            return cache
        nlist = IPR.get_neighbours(AF_INET, match=lambda x: x['state'] == 2, ifname=iface)
    else:
        nlist = IPR.get_neighbours(AF_INET, match=lambda x: x['state'] == 2)

    for n in nlist:
        try:
            # unpack attributes (list of tuples) into a dict for easier access
            attrs = {a[0]: a[1] for a in n['attrs']}
            n_ip  = IPv4Address(attrs['NDA_DST'])
            n_hw  = attrs['NDA_LLADDR']
            n_ttl = attrs['NDA_CACHEINFO']

            # neighbour interface
            if if_data is None or if_data['idx'] != n['ifindex']:
                if_data = get_interface(n['ifindex'])
            if_name = iface or if_data['name']

            # create a Neighbor object and populate it
            neigh = Neighbor(n_ip, hw=n_hw, iface=if_name, verbose=verbose, cached=True)
            neigh.if_ip = IPv4Address(if_data['ipaddr'][0]) if if_data['ipaddr'] else None
            neigh.if_hw = if_data['hwaddr']
            neigh.ttl = n_ttl
            if n_ip not in cache:
                cache[n_ip] = neigh
        except Exception as e:  # pylint: disable=broad-except
            if debug:
                eprint(f'DEBUG: could not parse ARP cache entry: {e}')

    return cache


def filter_cached(hosts: Iterable[IPv4Address], verbose: bool, debug: bool, iface: Optional[str]):
    """Filter out hosts that are already in ARP cache."""
    cached = get_arp_cache(verbose, debug, iface=iface)
    filtered = [h for h in hosts if h not in cached]
    removed  = set(hosts) - set(filtered)

    if debug and removed:
        eprint(f'DEBUG: skipping {len(removed)} hosts already in ARP cache')

    # TODO: integrate (relevant) cached neighbors into the results
    return filtered


def main():
    """Main function to run the ARP sweep process"""
    if os.geteuid() != 0:
        eprint("ERROR: root privileges are required to send (raw) ARP packets.")
        sys.exit(1)

    args = parse_cmdline_args()
    hosts: Iterable[IPv4Address] = set(args.net.hosts()) if args.rand else list(args.net.hosts())
    if args.neigh:
        hosts = filter_cached(hosts, verbose=args.verbose, debug=args.debug, iface=args.iface)

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
        headers = ['IP address', 'HW address', 'Recv', 'Time (ms)']
        for host, neigh in results.items():
            if neigh is not None:
                data.append([host, neigh.hw, len(neigh), f'{neigh.time*1e3:.4f}'])
        data.sort(key=lambda x: x[0])
        print(simple_tabulate(data, headers=headers))
    else:
        eprint("INFO: no responses received.")


if __name__ == "__main__":
    main()
