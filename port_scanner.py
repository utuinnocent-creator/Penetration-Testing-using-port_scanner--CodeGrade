#!/usr/bin/env python3
"""
port_scanner.py

A simple TCP port scanner for authorized penetration testing and
security assessments in a lab environment (e.g., Metasploitable 3).

Usage:
    python port_scanner.py <target> [start_port] [end_port]

If no command-line arguments are supplied, the script prompts for a
target IP address or domain name and scans the default port range.
"""

import socket
import sys

DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
CONNECTION_TIMEOUT = 1.0


def get_target_and_ports():
    """
    Determine the target and port range to scan.

    The target may be supplied as the first command-line argument,
    or entered interactively if no arguments are given. An optional
    start_port and end_port may also be passed on the command line;
    otherwise the default range is used.
    """
    args = sys.argv[1:]

    if len(args) >= 1:
        target = args[0]
    else:
        target = input("Enter target IP address or domain: ").strip()

    if len(args) >= 3:
        try:
            start_port = int(args[1])
            end_port = int(args[2])
        except ValueError:
            print("Invalid port numbers supplied on the command line. "
                  f"Using default range {DEFAULT_START_PORT}-"
                  f"{DEFAULT_END_PORT} instead.")
            start_port, end_port = DEFAULT_START_PORT, DEFAULT_END_PORT
    else:
        start_port, end_port = DEFAULT_START_PORT, DEFAULT_END_PORT

    return target, start_port, end_port


def resolve_target(target):
    """
    Resolve a hostname or IP address to an IP address string.

    Handles an invalid host gracefully: returns the resolved IP on
    success, or None if the host name or address cannot be resolved.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def scan_port(target_ip, port, timeout=CONNECTION_TIMEOUT):
    """
    Attempt a TCP connection to a single port on target_ip.

    Returns True if the port is open, False otherwise. Timeouts,
    refused connections, and general socket errors (e.g. an
    unreachable target) are all handled here so the scan never
    crashes on a single bad port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)

        try:
            s.connect((target_ip, port))
            return True
        except socket.error:
            # Handles all connection-related problems in one place:
            # timeouts, refused connections (closed ports), and
            # general socket errors such as an unreachable target.
            return False


def scan_port_range(target_ip, start_port, end_port):
    """
    Scan every port in [start_port, end_port] on target_ip.

    Returns a list of open ports found, printing a clearly labeled
    line for each one as it is discovered.
    """
    open_ports = []

    for port in range(start_port, end_port + 1):
        try:
            if scan_port(target_ip, port):
                print(f"[OPEN] Port {port} is open")
                open_ports.append(port)
        except KeyboardInterrupt:
            print("\nScan interrupted by user. Exiting.")
            sys.exit(1)

    return open_ports


def print_summary(target, target_ip, start_port, end_port, open_ports):
    """
    Print a clearly labeled summary of the scan results.
    """
    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    print(f"Target: {target} ({target_ip})")
    print(f"Port range: {start_port}-{end_port}")

    port_word = "port" if len(open_ports) == 1 else "ports"
    print(f"{len(open_ports)} open {port_word} found")

    if open_ports:
        print(f"Open ports: {', '.join(str(p) for p in open_ports)}")
    else:
        print("Open ports: None found")
    print("=" * 50)


def main():
    """
    Main entry point: gather input, resolve the target, run the
    scan, and print results. An invalid or unreachable host is
    handled gracefully instead of crashing the program.
    """
    target, start_port, end_port = get_target_and_ports()

    target_ip = resolve_target(target)
    if target_ip is None:
        print(f"Error: could not resolve host '{target}'. "
              "Please check the address and try again.")
        return

    print(f"\nScanning {target} ({target_ip}), "
          f"ports {start_port}-{end_port}...\n")

    open_ports = scan_port_range(target_ip, start_port, end_port)
    print_summary(target, target_ip, start_port, end_port, open_ports)


if __name__ == "__main__":
    main()
