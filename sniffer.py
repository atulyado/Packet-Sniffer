"""
Packet Sniffer - A beginner-friendly cybersecurity portfolio project.

This script captures live packets with Scapy, prints useful packet details,
logs them to a file, and performs a simple suspicious-activity check.

Ethical note:
Only sniff traffic on networks and devices you own or have permission to test.
Packet sniffing can expose sensitive information.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import platform
import sys
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, Optional

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # The program still works without colorful output.
    Fore = Style = None

    def colorama_init(*args, **kwargs):
        return None

try:
    from scapy.all import ICMP, IP, TCP, UDP, sniff
except ImportError:
    print("Scapy is not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


LOG_FILE = Path(__file__).with_name("logs.txt")
SUPPORTED_FILTERS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp"}


class PacketSniffer:
    """Keeps packet-sniffing state organized in one place."""

    def __init__(
        self,
        protocol_filter: Optional[str],
        packet_limit: int,
        interface: Optional[str],
        alert_threshold: int,
        alert_window: int,
        use_color: bool,
    ) -> None:
        self.protocol_filter = protocol_filter
        self.packet_limit = packet_limit
        self.interface = interface
        self.alert_threshold = alert_threshold
        self.alert_window = alert_window
        self.use_color = use_color

        self.packet_count = 0
        self.ip_activity: Dict[str, Deque[datetime]] = defaultdict(deque)

    def color(self, text: str, color_code: str) -> str:
        """Apply terminal color only when colorama is available and enabled."""
        if not self.use_color or Fore is None:
            return text
        return f"{color_code}{text}{Style.RESET_ALL}"

    def banner(self) -> None:
        """Print a professional-looking header before capture starts."""
        filter_label = self.protocol_filter.upper() if self.protocol_filter else "ALL"
        limit_label = "Unlimited" if self.packet_limit == 0 else str(self.packet_limit)
        interface_label = self.interface or "Default"

        print(self.color("=" * 72, Fore.CYAN if Fore else ""))
        print(self.color(" Packet Sniffer - Python + Scapy ".center(72), Fore.CYAN if Fore else ""))
        print(self.color("=" * 72, Fore.CYAN if Fore else ""))
        print(f"Interface       : {interface_label}")
        print(f"Protocol filter : {filter_label}")
        print(f"Packet limit    : {limit_label}")
        print(f"Log file        : {LOG_FILE}")
        print(self.color("-" * 72, Fore.CYAN if Fore else ""))
        print("Press Ctrl+C to stop capturing packets.\n")

    def write_log(self, message: str) -> None:
        """Append packet information and alerts to logs.txt."""
        with LOG_FILE.open("a", encoding="utf-8") as log_file:
            log_file.write(message + "\n")

    def identify_protocol(self, packet) -> str:
        """
        Detect the transport/network protocol.

        TCP and UDP are transport-layer protocols. ICMP is commonly used for
        diagnostics such as ping. These are frequent starting points for
        learning network monitoring.
        """
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        return "OTHER"

    def check_suspicious_activity(self, source_ip: str, timestamp: datetime) -> None:
        """
        Warn when one source IP sends many packets in a short time window.

        This is a basic rate-based signal. Real intrusion detection systems use
        richer context, but rate spikes are a useful beginner-friendly concept.
        """
        recent_packets = self.ip_activity[source_ip]
        recent_packets.append(timestamp)

        while recent_packets and (timestamp - recent_packets[0]).total_seconds() > self.alert_window:
            recent_packets.popleft()

        if len(recent_packets) == self.alert_threshold:
            warning = (
                f"[WARNING] Suspicious activity: {source_ip} sent "
                f"{len(recent_packets)} packets in {self.alert_window} seconds"
            )
            print(self.color(warning, Fore.RED if Fore else ""))
            self.write_log(f"{timestamp.isoformat(sep=' ', timespec='seconds')} | {warning}")

    def process_packet(self, packet) -> None:
        """
        Callback function passed to Scapy's sniff(prn=...).

        Scapy calls this function once for every captured packet. Packets that
        do not contain an IP layer are skipped because they do not have source
        and destination IP addresses.
        """
        if not packet.haslayer(IP):
            return

        self.packet_count += 1
        timestamp = datetime.now()
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = self.identify_protocol(packet)

        timestamp_text = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        line = (
            f"[{self.packet_count:05d}] {timestamp_text} | "
            f"SRC: {source_ip:<15} -> DST: {destination_ip:<15} | PROTOCOL: {protocol}"
        )

        protocol_color = {
            "TCP": Fore.GREEN if Fore else "",
            "UDP": Fore.YELLOW if Fore else "",
            "ICMP": Fore.MAGENTA if Fore else "",
            "OTHER": Fore.WHITE if Fore else "",
        }.get(protocol, "")

        print(self.color(line, protocol_color))
        self.write_log(line)
        self.check_suspicious_activity(source_ip, timestamp)

    def start(self) -> None:
        """
        Start live capture with Scapy.

        store=False prevents Scapy from keeping all packets in memory. This is
        better for long-running monitoring because packet lists can grow fast.
        """
        self.banner()
        self.write_log("\n" + "=" * 72)
        self.write_log(f"Capture started at {datetime.now().isoformat(sep=' ', timespec='seconds')}")

        bpf_filter = SUPPORTED_FILTERS.get(self.protocol_filter) if self.protocol_filter else None

        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.process_packet,
                store=False,
                count=self.packet_limit,
            )
        except KeyboardInterrupt:
            print(self.color("\nCapture stopped by user.", Fore.CYAN if Fore else ""))
        except PermissionError:
            print_error("Permission denied. Run this script as Administrator/root.")
        except OSError as error:
            print_error(
                "Packet capture failed. Check your interface name, permissions, "
                f"and packet capture driver. Details: {error}"
            )
        except Exception as error:  # Keeps beginner-facing errors readable.
            print_error(f"Unexpected error: {error}")
        finally:
            summary = f"Capture finished. Total IP packets captured: {self.packet_count}"
            print(self.color(summary, Fore.CYAN if Fore else ""))
            self.write_log(f"{datetime.now().isoformat(sep=' ', timespec='seconds')} | {summary}")


def print_error(message: str) -> None:
    """Print a consistent error message."""
    if Fore is None:
        print(f"[ERROR] {message}")
    else:
        print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")


def is_running_with_admin_rights() -> bool:
    """
    Check whether the script has elevated privileges.

    Sniffing needs elevated permissions because operating systems protect raw
    network access. On Windows this usually means Administrator; on Linux/macOS
    it usually means root or capabilities such as CAP_NET_RAW.
    """
    system = platform.system().lower()

    if system == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    if hasattr(os, "geteuid"):
        return os.geteuid() == 0

    return False


def parse_arguments() -> argparse.Namespace:
    """Create a beginner-friendly command-line interface."""
    parser = argparse.ArgumentParser(
        description="Capture and inspect live network packets with Scapy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--filter",
        choices=sorted(SUPPORTED_FILTERS.keys()),
        help="Capture only one protocol type.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture. Use 0 for unlimited capture.",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to sniff on. Leave empty to use Scapy's default.",
    )
    parser.add_argument(
        "--alert-threshold",
        type=int,
        default=20,
        help="Warn when one IP sends this many packets inside the alert window.",
    )
    parser.add_argument(
        "--alert-window",
        type=int,
        default=10,
        help="Suspicious activity time window in seconds.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colorful terminal output.",
    )
    parser.add_argument(
        "--skip-admin-check",
        action="store_true",
        help="Try to run even if elevated permissions are not detected.",
    )
    return parser.parse_args()


def main() -> None:
    """Program entry point."""
    args = parse_arguments()
    colorama_init(autoreset=True)

    if args.count < 0:
        print_error("Packet count cannot be negative.")
        sys.exit(1)

    if args.alert_threshold <= 0 or args.alert_window <= 0:
        print_error("Alert threshold and alert window must be positive numbers.")
        sys.exit(1)

    if not args.skip_admin_check and not is_running_with_admin_rights():
        print_error(
            "Administrator/root permissions were not detected. "
            "Run with elevated privileges, or use --skip-admin-check to try anyway."
        )
        sys.exit(1)

    sniffer = PacketSniffer(
        protocol_filter=args.filter,
        packet_limit=args.count,
        interface=args.interface,
        alert_threshold=args.alert_threshold,
        alert_window=args.alert_window,
        use_color=not args.no_color,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
