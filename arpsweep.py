#!/usr/bin/env python3

"""
Functionality:
  - ARP sweep of a subnet
"""

from __future__ import annotations

__author__    = "Mikko Tanner"
__copyright__ = f"(c) {__author__} 2025"
__version__   = "0.2.0-1_20250605"
__license__   = "GPL-3.0-or-later"

import json
import os
#import subprocess
import sys
from argparse import ArgumentParser
from ipaddress import (IPv4Address, IPv4Network)
from typing import Any, Dict, Iterable, List, Set

from scapy.all import srp
from scapy.layers.l2 import ARP, Ether

# Are we running in a terminal?
HAVE_TTY = sys.stdout.isatty()


def parse_cmdline_args():
    """Parse command-line arguments."""

    args = ArgumentParser(description='ARP sweep of a subnet')
    args.add_argument('cidr', help='CIDR network address to scan')
    args.add_argument('--iface', '-I', help='Interface to use (default: autoselect)')
    args.add_argument('--src', '-S', help='Source IP to use (default: autoselect)')
    args.add_argument('--count', type=int, default=1, help='Number of ARP reqs (default: 1)')
    args.add_argument('--timeout', type=int, default=1,
                      help='ARP timeout in seconds (default: 1)')
    args.add_argument('--rand', action='store_true', help='Sweep hosts in random order')
    args.add_argument('--batch', '-B', action='store_true', help='Batch mode - no output')
    args.add_argument('--json', action='store_true', help='JSON output')
    args.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args.add_argument('--debug', action='store_true', help='Debug mode - extra verbose')
    args.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    p = args.parse_args()

    p.cidr = IPv4Network(p.cidr)
    p.src  = IPv4Address(p.src) if p.src else None

    # we don't wait for answers in batch mode, nor do we want to output anything
    if p.batch:
        p.count = 1
        p.timeout = 0
        p.verbose = p.debug = p.json = False

    if p.debug:
        p.verbose = True

    return p


def eprint(*values, **kwargs):
    """Mimic print() but write to stderr."""
    print(*values, file=sys.stderr, **kwargs)


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
        })

    if verbose and responses:
        r = responses[0]
        eprint(f"{r['src_ip']} is-at {r['src_hw']} (resp: type={r['type']}, len={r['len']})")

    return responses


def create_arp_packets(bc, host: IPv4Address, num: int, src: IPv4Address | None):
    """Create ARP request packet(s) for a given host."""
    return [bc / ARP(pdst=str(host), hwsrc=str(src) if src else None)] * num


def do_arp_sweep(hosts: Iterable[IPv4Address], args):
    """Perform an ARP sweep on the specified hosts."""
    ether_bc = Ether(dst="ff:ff:ff:ff:ff:ff")
    responses: Dict[str, List[Dict[str, Any]] | None] = {}

    for host in hosts:
        pkts = create_arp_packets(ether_bc, host=host, num=args.count, src=args.src)
        resp = send_packets(pkts, timeout=args.timeout, iface=args.iface, verbose=args.verbose)
        if resp:
            responses[str(host)] = resp
        else:
            responses[str(host)] = None

        if args.debug:
            if resp:
                srcip = resp[0]['dst_ip']
                eprint(f'DEBUG: sent {len(pkts)} ARP packets to {host} (src: {srcip}),',
                       f'received {len(resp)} responses')
            else:
                eprint(f'DEBUG: no responses received for {host}')

    return responses


def main():
    """Main function to run the ARP sweep process"""
    if os.geteuid() != 0:
        eprint("ERROR: root privileges are required to send (raw) ARP packets.")
        sys.exit(1)

    args = parse_cmdline_args()
    hosts: Iterable[IPv4Address] = set(args.cidr.hosts()) if args.rand else list(args.cidr.hosts())

    if args.verbose and HAVE_TTY:
        eprint(f'INFO: scanning {args.cidr} (net: {args.cidr.network_address},',
               f'bcast: {args.cidr.broadcast_address}, hosts: {len(hosts)})')

    results = do_arp_sweep(hosts=hosts, args=args)

    if args.batch:
        sys.exit(0)
    elif args.json:
        print(json.dumps(results, indent=2 if HAVE_TTY else None))
    elif any(val is not None for val in results.values()):
        data = []
        headers = ['IP Address', 'MAC Address', 'Responses']
        for host, responses in results.items():
            if responses is not None:
                resp = responses[0]
                data.append([host, resp['src_hw'], len(responses)])
        print(simple_tabulate(data, headers=headers))
    else:
        eprint("INFO: no responses received.")


if __name__ == "__main__":
    main()
