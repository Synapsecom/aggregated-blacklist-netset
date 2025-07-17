#! /usr/bin/env python3
# Author: Sotirios Roussis <s.roussis@synapsecom.gr>

"""
collapser.py - Collapse & deduplicate IPv4/IPv6 prefixes.

Usage:
    python3 collapse_ipset.py  [-i INPUT] [-o OUTPUT]

If -i/--input is omitted, reads from STDIN.
If -o/--output is omitted, writes to STDOUT.

Lines that don't contain an IP/CIDR token are ignored.
"""

import re
import sys
import ipaddress
import argparse

from typing import Iterable, List, Union


IPV4_RGXP = r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
IPV6_RGXP = r"(?:[0-9A-Fa-f]{1,4}:){1,7}[0-9A-Fa-f]{1,4}(?:/\d{1,3})?"

# Regex for the *first* IP or IP/CIDR token on a line
TOKEN_RGXP = re.compile(f"(?:{IPV4_RGXP})|(?:{IPV6_RGXP})")


def parse_token(token: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network, None, ]:
    """Return ipaddress.ip_network with added /32 or /128 when missing."""
    if "/" not in token:
        token += "/128" if ":" in token else "/32"

    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def collapse_stream(lines: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    """Extract tokens, add masks, dedup, collapse v4 & v6 separately."""
    v4, v6 = set(), set()

    for line in lines:
        m = TOKEN_RGXP.search(line)
        if not m:
            continue

        net = parse_token(m.group(0))
        if not net:
            continue

        (v4 if net.version == 4 else v6).add(net)

    collapsed_v4 = ipaddress.collapse_addresses(
        sorted(v4, key=lambda n: int(n.network_address))
    )
    collapsed_v6 = ipaddress.collapse_addresses(
        sorted(v6, key=lambda n: int(n.network_address))
    )

    # Return IPv4 first, then IPv6
    return list(collapsed_v4) + list(collapsed_v6)


def main() -> None:
    ap = argparse.ArgumentParser(description="Collapse & deduplicate IP/CIDR lists")
    ap.add_argument("-i", "--input",  help="input file (default: STDIN)")
    ap.add_argument("-o", "--output", help="output file (default: STDOUT)")
    args = ap.parse_args()

    # Input
    if args.input:
        with open(args.input, encoding="utf-8") as fh:
            lines = fh.readlines()
    else:
        lines = sys.stdin.readlines()

    collapsed = collapse_stream(lines)

    # Output
    out_fh = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    for net in collapsed:
        out_fh.write(f"{net.with_prefixlen}\n")
    if out_fh is not sys.stdout:
        out_fh.close()


if __name__ == "__main__":
    main()
