"""A small Tkinter utility for pinging hosts and recording results."""

from __future__ import annotations

import csv
import ipaddress
import json
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
import tkinter as tk
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Callable, cast

APP_DIR = Path(__file__).resolve().parent
LOG_PATH = APP_DIR / "network_diagnostic_history.csv"
LEGACY_LOG_PATH = APP_DIR / "network_test_log.csv"
TARGETS_PATH = APP_DIR / "saved_targets.json"
HISTORY_FIELDS = [
    "timestamp",
    "test_type",
    "target",
    "status",
    "details",
    "sent",
    "received",
    "packet_loss_percent",
    "average_latency_ms",
    "minimum_latency_ms",
    "maximum_latency_ms",
    "port",
    "source_address",
]

_LATENCY_PATTERN = re.compile(r"time\s*([=<])\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
_DNS_NAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?"
)


@dataclass(frozen=True)
class PingResult:
    timestamp: str
    host: str
    status: str
    sent: int
    received: int
    packet_loss_percent: float
    average_latency_ms: float | None
    minimum_latency_ms: float | None
    maximum_latency_ms: float | None
    source_address: str | None = None


@dataclass(frozen=True)
class TcpResult:
    is_open: bool
    latency_ms: float | None
    details: str


@dataclass(frozen=True)
class NetworkAdapter:
    name: str
    ipv4: tuple[str, ...]
    gateways: tuple[str, ...]
    dns_servers: tuple[str, ...]


@dataclass(frozen=True)
class ConnectivityResult:
    status: str
    details: str


def timestamp_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def get_network_adapters() -> list[NetworkAdapter]:
    if platform.system() == "Windows":
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
        if powershell is None:
            raise FileNotFoundError("PowerShell was not found; adapter details are unavailable.")
        script = (
            "$ErrorActionPreference='Stop'; "
            "Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq 'Up'} | "
            "ForEach-Object {[PSCustomObject]@{"
            "Name=$_.InterfaceAlias; "
            "IPv4=@($_.IPv4Address | ForEach-Object {\"$($_.IPAddress)/$($_.PrefixLength)\"}); "
            "Gateways=@($_.IPv4DefaultGateway | ForEach-Object {$_.NextHop}); "
            "DNS=@($_.DNSServer.ServerAddresses)"
            "}} | ConvertTo-Json -Depth 3 -Compress"
        )
        try:
            completed = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Adapter discovery timed out while querying Windows network configuration.") from error
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "Could not read network adapter configuration.")
        data = json.loads(completed.stdout) if completed.stdout.strip() else []
        items = data if isinstance(data, list) else [data]
        return [
            NetworkAdapter(
                name=str(item.get("Name", "Unknown adapter")),
                ipv4=tuple(str(value) for value in _as_list(item.get("IPv4")) if value),
                gateways=tuple(str(value) for value in _as_list(item.get("Gateways")) if value),
                dns_servers=tuple(str(value) for value in _as_list(item.get("DNS")) if value),
            )
            for item in items
        ]

    ip_command = shutil.which("ip")
    if ip_command is None:
        raise FileNotFoundError("The 'ip' command is required to read adapter details on this system.")
    addresses = subprocess.run(
        [ip_command, "-j", "address", "show"], capture_output=True, text=True, errors="replace", timeout=5, check=True
    )
    routes = subprocess.run(
        [ip_command, "-j", "route", "show", "default"], capture_output=True, text=True, errors="replace", timeout=5, check=True
    )
    route_by_interface = {
        route.get("dev"): route.get("gateway") for route in json.loads(routes.stdout) if route.get("dev")
    }
    dns_servers: list[str] = []
    resolv_conf = Path("/etc/resolv.conf")
    if resolv_conf.exists():
        dns_servers = [
            line.split()[1]
            for line in resolv_conf.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.startswith("nameserver ") and len(line.split()) > 1
        ]
    result = []
    for interface in json.loads(addresses.stdout):
        name = str(interface.get("ifname", "Unknown adapter"))
        if name == "lo":
            continue
        ipv4 = tuple(
            f"{address['local']}/{address['prefixlen']}"
            for address in interface.get("addr_info", [])
            if address.get("family") == "inet" and address.get("local")
        )
        gateway = route_by_interface.get(name)
        result.append(NetworkAdapter(name, ipv4, (gateway,) if gateway else (), tuple(dns_servers)))
    return result


def format_network_overview(adapters: list[NetworkAdapter]) -> str:
    if not adapters:
        return "No active network adapters were found."
    sections = []
    for adapter in adapters:
        sections.append(
            "\n".join(
                (
                    adapter.name,
                    f"  IPv4 / prefix: {', '.join(adapter.ipv4) or 'Not assigned'}",
                    f"  Default gateway: {', '.join(adapter.gateways) or 'Not available'}",
                    f"  DNS servers: {', '.join(adapter.dns_servers) or 'Not available'}",
                )
            )
        )
    return "\n\n".join(sections)


def check_gateway_dns(dns_host: str) -> ConnectivityResult:
    adapters = get_network_adapters()
    gateway = next((gateway for adapter in adapters for gateway in adapter.gateways), None)
    lines = []
    gateway_ok = False
    if gateway:
        try:
            gateway_result = run_ping(gateway, count=1, timeout_ms=1000)
            gateway_ok = gateway_result.received > 0
            lines.append(f"Default gateway {gateway}: {gateway_result.status}")
        except (OSError, subprocess.SubprocessError) as error:
            lines.append(f"Default gateway {gateway}: check failed ({error})")
    else:
        lines.append("Default gateway: not found")
    try:
        addresses = lookup_dns(dns_host)
        dns_ok = bool(addresses)
        lines.append(f"DNS lookup for {dns_host}: " + (", ".join(addresses) if addresses else "no addresses returned"))
    except (OSError, ValueError) as error:
        dns_ok = False
        lines.append(f"DNS lookup for {dns_host}: failed ({error})")
    status = "Passed" if gateway_ok and dns_ok else "Needs attention"
    return ConnectivityResult(status, "\n".join(lines))


def load_saved_targets() -> list[dict[str, str | int]]:
    if not TARGETS_PATH.exists():
        return []
    try:
        targets = json.loads(TARGETS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(targets, list):
        return []
    valid_targets = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        name = target.get("name")
        host = target.get("host")
        port = target.get("port")
        if not isinstance(name, str) or not name.strip() or not isinstance(host, str) or not validate_target(host):
            continue
        if not isinstance(port, int) or not 1 <= port <= 65535:
            continue
        try:
            ping_count = int(target.get("ping_count", 4))
            timeout_ms = int(target.get("timeout_ms", 1000))
            interval = int(target.get("interval_seconds", 1))
            latency_alert = float(target.get("alert_latency_ms", 150))
            loss_alert = int(target.get("alert_loss_percent", 10))
        except (TypeError, ValueError):
            continue
        if not 1 <= ping_count <= 20 or not 250 <= timeout_ms <= 10000 or not 1 <= interval <= 300:
            continue
        if latency_alert <= 0 or not 0 <= loss_alert <= 100:
            continue
        source_address = target.get("source_address", "")
        if source_address:
            try:
                if ipaddress.ip_address(str(source_address)).version != 4:
                    continue
            except ValueError:
                continue
        valid_targets.append(
            {
                "name": name.strip(),
                "host": host,
                "port": port,
                "ping_count": ping_count,
                "timeout_ms": timeout_ms,
                "interval_seconds": interval,
                "alert_latency_ms": latency_alert,
                "alert_loss_percent": loss_alert,
                "source_address": str(source_address),
            }
        )
    return valid_targets


def save_targets(targets: list[dict[str, str | int]]) -> None:
    TARGETS_PATH.write_text(json.dumps(targets, indent=2), encoding="utf-8")


def validate_target(target: str) -> bool:
    """Accept an IP address or DNS name, but not ping command options."""
    target = target.strip()
    if not target:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(_DNS_NAME_PATTERN.fullmatch(target))


def parse_ping_output(output: str) -> list[float]:
    """Extract reply times from common Windows and Unix ping output."""
    latencies = []
    for match in _LATENCY_PATTERN.finditer(output):
        latency = float(match.group(2))
        if match.group(1) == "<":
            latency = min(latency / 2, 0.5)
        latencies.append(latency)
    return latencies


def run_ping(host: str, count: int, timeout_ms: int, source_address: str | None = None) -> PingResult:
    if not validate_target(host):
        raise ValueError("Enter a valid IP address or DNS hostname.")
    if not 1 <= count <= 20:
        raise ValueError("Ping count must be between 1 and 20.")
    if not 250 <= timeout_ms <= 10000:
        raise ValueError("Timeout must be between 250 and 10000 milliseconds.")
    if source_address is not None:
        try:
            if ipaddress.ip_address(source_address).version != 4:
                raise ValueError
        except ValueError as error:
            raise ValueError("Choose a valid local IPv4 adapter address.") from error

    if platform.system() == "Windows":
        command = ["ping"]
        if source_address:
            command.extend(("-S", source_address))
        command.extend(("-n", str(count), "-w", str(timeout_ms), host))
    else:
        command = ["ping"]
        if source_address:
            command.extend(("-I", source_address))
        command.extend(("-c", str(count), host))

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=(timeout_ms / 1000) * count + 5,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    latencies = parse_ping_output(output)[:count]
    received = len(latencies)
    loss = ((count - received) / count) * 100
    average = sum(latencies) / received if received else None

    return PingResult(
        timestamp=timestamp_now(),
        host=host,
        status="Online" if received else "No reply",
        sent=count,
        received=received,
        packet_loss_percent=loss,
        average_latency_ms=average,
        minimum_latency_ms=min(latencies) if latencies else None,
        maximum_latency_ms=max(latencies) if latencies else None,
        source_address=source_address,
    )


def ping_history_row(result: PingResult, test_type: str = "Ping") -> dict[str, str | int | float]:
    details = f"{result.received}/{result.sent} replies"
    if result.source_address:
        details += f" via {result.source_address}"
    return {
        "timestamp": result.timestamp,
        "test_type": test_type,
        "target": result.host,
        "status": result.status,
        "details": details,
        "sent": result.sent,
        "received": result.received,
        "packet_loss_percent": result.packet_loss_percent,
        "average_latency_ms": result.average_latency_ms if result.average_latency_ms is not None else "",
        "minimum_latency_ms": result.minimum_latency_ms if result.minimum_latency_ms is not None else "",
        "maximum_latency_ms": result.maximum_latency_ms if result.maximum_latency_ms is not None else "",
        "port": "",
        "source_address": result.source_address or "",
    }


def append_history(row: dict[str, str | int | float]) -> None:
    write_header = not LOG_PATH.exists() or LOG_PATH.stat().st_size == 0
    with LOG_PATH.open("a", newline="", encoding="utf-8") as log_file:
        writer = csv.DictWriter(log_file, fieldnames=HISTORY_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def load_history() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if LOG_PATH.exists():
        with LOG_PATH.open("r", newline="", encoding="utf-8") as log_file:
            rows.extend(csv.DictReader(log_file))
    if LEGACY_LOG_PATH.exists():
        with LEGACY_LOG_PATH.open("r", newline="", encoding="utf-8") as log_file:
            for old_row in csv.DictReader(log_file):
                rows.append(
                    {
                        "timestamp": old_row.get("timestamp", ""),
                        "test_type": "Ping",
                        "target": old_row.get("host", ""),
                        "status": old_row.get("status", ""),
                        "details": f"{old_row.get('received', '?')}/{old_row.get('sent', '?')} replies",
                        "sent": old_row.get("sent", ""),
                        "received": old_row.get("received", ""),
                        "packet_loss_percent": old_row.get("packet_loss_percent", ""),
                        "average_latency_ms": old_row.get("average_latency_ms", ""),
                        "minimum_latency_ms": old_row.get("minimum_latency_ms", ""),
                        "maximum_latency_ms": old_row.get("maximum_latency_ms", ""),
                        "port": "",
                        "source_address": "",
                    }
                )
    return sorted(rows, key=lambda row: row.get("timestamp", ""), reverse=True)


def lookup_dns(host: str) -> list[str]:
    if not validate_target(host):
        raise ValueError("Enter a valid IP address or DNS hostname.")
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({record[4][0] for record in addresses})


def check_tcp_port(
    host: str,
    port: int,
    timeout: float = 3.0,
    source_address: str | None = None,
) -> TcpResult:
    if not validate_target(host):
        raise ValueError("Enter a valid IP address or DNS hostname.")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if source_address is not None:
        try:
            if ipaddress.ip_address(source_address).version != 4:
                raise ValueError
        except ValueError as error:
            raise ValueError("Choose a valid local IPv4 adapter address.") from error
    started = time.perf_counter()
    try:
        if source_address:
            connection = socket.create_connection((host, port), timeout=timeout, source_address=(source_address, 0))
        else:
            connection = socket.create_connection((host, port), timeout=timeout)
        with connection:
            latency = (time.perf_counter() - started) * 1000
        return TcpResult(True, latency, "TCP connection accepted.")
    except (OSError, TimeoutError) as error:
        return TcpResult(False, None, str(error) or "Connection refused or timed out.")


def run_traceroute(host: str, max_hops: int = 20, timeout_ms: int = 1000) -> str:
    if not validate_target(host):
        raise ValueError("Enter a valid IP address or DNS hostname.")
    if not 1 <= max_hops <= 30:
        raise ValueError("Maximum hops must be between 1 and 30.")
    if not 250 <= timeout_ms <= 5000:
        raise ValueError("Hop timeout must be between 250 and 5000 milliseconds.")

    is_windows = platform.system() == "Windows"
    executable = "tracert" if is_windows else "traceroute"
    if shutil.which(executable) is None:
        raise FileNotFoundError(f"'{executable}' was not found on PATH.")
    if is_windows:
        command = [executable, "-d", "-h", str(max_hops), "-w", str(timeout_ms), host]
    else:
        command = [executable, "-n", "-m", str(max_hops), "-w", str(timeout_ms / 1000), host]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=max_hops * (timeout_ms / 1000 + 1) + 5,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    output = (completed.stdout + "\n" + completed.stderr).strip()
    if not output:
        raise RuntimeError(f"Traceroute exited with code {completed.returncode} and returned no output.")
    return output


def format_latency(value: float | None) -> str:
    return f"{value:.2f} ms" if value is not None else "N/A"


class NetworkDiagnosticApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Network Diagnostic Tool")
        self.root.geometry("1120x820")
        self.root.minsize(920, 700)
        self.root.configure(bg="#edf1ef")
        self.latest_result: PingResult | None = None
        self.latest_report: str | None = None
        self.history_rows: list[dict[str, str]] = []
        self.visible_history_rows: list[dict[str, str]] = []
        self.monitor_stop_event: threading.Event | None = None
        self.monitor_samples: list[PingResult] = []
        self.monitor_window: tk.Toplevel | None = None
        self.monitor_alert_active = False
        self.history_item_rows: dict[str, dict[str, str]] = {}
        self.saved_targets: list[dict[str, str | int]] = []
        self.interface_sources: dict[str, str | None] = {"Default route": None}
        self.preferred_source_address: str | None = None
        self.alert_latency_var = tk.DoubleVar(root, value=150)
        self.alert_loss_var = tk.IntVar(root, value=10)
        self.monitor_interval_pref = tk.IntVar(root, value=1)
        self.session_events: list[str] = []
        self.monitor_error_active = False
        self._configure_styles()
        self._build_layout()
        self._refresh_saved_targets()
        self._load_history()
        self._bind_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)
        threading.Thread(target=self._discover_interfaces, daemon=True).start()

    def _safe_after(self, callback: Callable[..., object], *args: object) -> None:
        if getattr(self, "_closing", False):
            return
        try:
            self.root.after(0, callback, *args)
        except tk.TclError:
            pass

    def close_app(self) -> None:
        self._closing = True
        if self.monitor_stop_event is not None:
            self.monitor_stop_event.set()
        self.root.destroy()

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#edf1ef")
        style.configure("Panel.TFrame", background="#ffffff")
        style.configure("TLabel", background="#edf1ef", foreground="#172321", font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background="#ffffff", foreground="#172321", font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background="#ffffff", foreground="#64736f", font=("Segoe UI", 9))
        style.configure("Stat.TLabel", background="#ffffff", foreground="#172321", font=("Segoe UI", 21, "bold"))
        style.configure("StatCaption.TLabel", background="#ffffff", foreground="#64736f", font=("Segoe UI", 9))
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 9), background="#ffffff", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#e6ece9", foreground="#34433f")
        style.map("Treeview", background=[("selected", "#d9eee5")], foreground=[("selected", "#172321")])
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 9), background="#187653", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#126244"), ("disabled", "#9eb9ae")])
        style.configure("TButton", font=("Segoe UI", 9), padding=(9, 6))
        style.configure("TEntry", padding=7)
        style.configure("TSpinbox", padding=5)

    def _build_layout(self) -> None:
        header = tk.Frame(self.root, bg="#172321", height=88)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header,
            text="NETWORK DIAGNOSTICS",
            bg="#172321",
            fg="#ffffff",
            font=("Segoe UI", 17, "bold"),
        ).pack(anchor="w", padx=28, pady=(18, 0))
        tk.Label(
            header,
            text="HOST REACHABILITY  /  LATENCY  /  PACKET LOSS",
            bg="#172321",
            fg="#a9c2b8",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=29, pady=(3, 0))

        content = ttk.Frame(self.root, padding=(24, 20, 24, 22))
        content.pack(fill="both", expand=True)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(1, weight=1)

        controls = ttk.Frame(content, style="Panel.TFrame", padding=18)
        controls.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 18))
        controls.configure(width=265)
        controls.grid_propagate(False)
        ttk.Label(controls, text="NEW TEST", style="Muted.TLabel").pack(anchor="w", pady=(0, 15))
        ttk.Label(controls, text="Host or IP address", style="Panel.TLabel").pack(anchor="w")
        self.host_var = tk.StringVar(value="1.1.1.1")
        self.host_entry = ttk.Entry(controls, textvariable=self.host_var)
        self.host_entry.pack(fill="x", pady=(5, 15))
        self.host_entry.bind("<Return>", lambda _event: self.start_test())
        ttk.Label(controls, text="Network interface", style="Panel.TLabel").pack(anchor="w")
        self.interface_var = tk.StringVar(value="Default route")
        self.interface_combo = ttk.Combobox(
            controls,
            textvariable=self.interface_var,
            values=("Default route",),
            state="readonly",
        )
        self.interface_combo.pack(fill="x", pady=(5, 15))

        options = ttk.Frame(controls, style="Panel.TFrame")
        options.pack(fill="x", pady=(0, 17))
        options.columnconfigure((0, 1), weight=1)
        ttk.Label(options, text="Packets", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(options, text="Timeout (ms)", style="Panel.TLabel").grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.count_var = tk.IntVar(value=4)
        self.timeout_var = tk.IntVar(value=1000)
        ttk.Spinbox(options, from_=1, to=20, textvariable=self.count_var, width=7).grid(row=1, column=0, sticky="ew", pady=(5, 0))
        ttk.Spinbox(options, from_=250, to=10000, increment=250, textvariable=self.timeout_var, width=9).grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(5, 0))

        self.run_button = ttk.Button(controls, text="Run diagnostic", style="Accent.TButton", command=self.start_test)
        self.run_button.pack(fill="x")
        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(controls, textvariable=self.progress_var, style="Muted.TLabel", wraplength=220).pack(anchor="w", pady=(10, 18))
        ttk.Separator(controls).pack(fill="x", pady=(0, 14))
        ttk.Label(controls, text="LATEST RESULT", style="Muted.TLabel").pack(anchor="w", pady=(0, 10))
        self.result_status = tk.StringVar(value="No test run")
        ttk.Label(controls, textvariable=self.result_status, style="Panel.TLabel", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        self.result_detail = tk.StringVar(value="Run a test to see host details.")
        ttk.Label(controls, textvariable=self.result_detail, style="Muted.TLabel", wraplength=220, justify="left").pack(anchor="w", pady=(5, 15))
        ttk.Button(controls, text="Export diagnostic report", command=self.export_report).pack(fill="x")
        ttk.Separator(controls).pack(fill="x", pady=(14, 12))
        ttk.Label(controls, text="QUICK CHECKS", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.dns_button = ttk.Button(controls, text="DNS lookup", command=self.start_dns_lookup)
        self.dns_button.pack(fill="x", pady=(0, 6))
        port_row = ttk.Frame(controls, style="Panel.TFrame")
        port_row.pack(fill="x", pady=(0, 6))
        ttk.Label(port_row, text="TCP port", style="Panel.TLabel").pack(side="left")
        self.port_var = tk.StringVar(value="443")
        ttk.Spinbox(port_row, from_=1, to=65535, textvariable=self.port_var, width=8).pack(side="right")
        self.tcp_button = ttk.Button(controls, text="Check TCP port", command=self.start_tcp_check)
        self.tcp_button.pack(fill="x", pady=(0, 6))
        trace_row = ttk.Frame(controls, style="Panel.TFrame")
        trace_row.pack(fill="x", pady=(0, 6))
        ttk.Label(trace_row, text="Max hops", style="Panel.TLabel").pack(side="left")
        self.hops_var = tk.IntVar(value=20)
        ttk.Spinbox(trace_row, from_=1, to=30, textvariable=self.hops_var, width=8).pack(side="right")
        self.trace_button = ttk.Button(controls, text="Run traceroute", command=self.start_traceroute)
        self.trace_button.pack(fill="x", pady=(0, 6))
        self.monitor_button = ttk.Button(controls, text="Continuous monitor", command=self.open_monitor)
        self.monitor_button.pack(fill="x")
        ttk.Label(controls, text=f"History: {LOG_PATH.name}", style="Muted.TLabel", wraplength=220).pack(anchor="w", pady=(12, 0))

        stats = ttk.Frame(content, style="Panel.TFrame", padding=(18, 14))
        stats.grid(row=0, column=1, sticky="ew", pady=(0, 16))
        for column in range(3):
            stats.columnconfigure(column, weight=1)
        self.stat_vars = [tk.StringVar(value="--") for _ in range(3)]
        captions = ("AVERAGE LATENCY", "PACKET LOSS", "REPLIES")
        for column, caption in enumerate(captions):
            ttk.Label(stats, textvariable=self.stat_vars[column], style="Stat.TLabel").grid(row=0, column=column, sticky="w")
            ttk.Label(stats, text=caption, style="StatCaption.TLabel").grid(row=1, column=column, sticky="w", pady=(2, 0))

        workspace = ttk.Notebook(content)
        self.workspace = workspace
        workspace.grid(row=1, column=1, sticky="nsew")
        history = ttk.Frame(workspace, style="Panel.TFrame", padding=16)
        workspace.add(history, text="History")
        history.rowconfigure(1, weight=1)
        history.columnconfigure(0, weight=1)
        heading = ttk.Frame(history, style="Panel.TFrame")
        heading.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(heading, text="TEST HISTORY", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        self.history_search_var = tk.StringVar()
        search_entry = ttk.Entry(heading, textvariable=self.history_search_var, width=19)
        search_entry.grid(row=0, column=1, padx=(14, 6), sticky="ew")
        search_entry.insert(0, "")
        self.history_type_var = tk.StringVar(value="All types")
        type_filter = ttk.Combobox(
            heading,
            textvariable=self.history_type_var,
            values=("All types", "Ping", "Monitor ping", "DNS lookup", "TCP port", "Traceroute", "Local overview", "Gateway + DNS"),
            state="readonly",
            width=13,
        )
        type_filter.grid(row=0, column=2, padx=4)
        ttk.Button(heading, text="Export CSV", command=self.export_history).grid(row=0, column=3, padx=4)
        ttk.Button(heading, text="Refresh", command=self._load_history).grid(row=0, column=4, padx=(4, 0))
        ttk.Button(heading, text="Compare 2", command=self.compare_selected_history).grid(row=0, column=5, padx=(4, 0))
        heading.columnconfigure(1, weight=1)
        self.history_search_var.trace_add("write", lambda *_args: self._apply_history_filter())
        type_filter.bind("<<ComboboxSelected>>", lambda _event: self._apply_history_filter())

        columns = ("timestamp", "test_type", "target", "status", "details", "latency", "loss")
        self.history = ttk.Treeview(history, columns=columns, show="headings", height=12, selectmode="extended")
        headings = {
            "timestamp": ("TIME", 150),
            "test_type": ("TYPE", 105),
            "target": ("TARGET", 130),
            "status": ("STATUS", 105),
            "details": ("DETAILS", 190),
            "latency": ("LATENCY", 95),
            "loss": ("LOSS", 65),
        }
        for column, (label, width) in headings.items():
            self.history.heading(column, text=label)
            self.history.column(column, width=width, minwidth=55, anchor="w", stretch=column in ("target", "details"))
        scrollbar = ttk.Scrollbar(history, orient="vertical", command=self.history.yview)
        self.history.configure(yscrollcommand=scrollbar.set)
        self.history.grid(row=1, column=0, sticky="nsew")
        scrollbar.grid(row=1, column=1, sticky="ns")

        network_page = ttk.Frame(workspace, style="Panel.TFrame", padding=20)
        self.network_page = network_page
        workspace.add(network_page, text="Network")
        network_page.columnconfigure(0, weight=1)
        network_page.rowconfigure(1, weight=1)
        overview_header = ttk.Frame(network_page, style="Panel.TFrame")
        overview_header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(overview_header, text="LOCAL ADAPTERS", style="Muted.TLabel").pack(side="left")
        self.overview_button = ttk.Button(overview_header, text="Refresh overview", command=self.start_network_overview)
        self.overview_button.pack(side="right")
        overview_body = ttk.Frame(network_page, style="Panel.TFrame")
        overview_body.grid(row=1, column=0, sticky="nsew")
        overview_body.rowconfigure(0, weight=1)
        overview_body.columnconfigure(0, weight=1)
        self.overview_text = tk.Text(overview_body, wrap="word", height=8, font=("Consolas", 10), padx=10, pady=10)
        overview_scroll = ttk.Scrollbar(overview_body, orient="vertical", command=self.overview_text.yview)
        self.overview_text.configure(yscrollcommand=overview_scroll.set, state="disabled")
        self.overview_text.grid(row=0, column=0, sticky="nsew")
        overview_scroll.grid(row=0, column=1, sticky="ns")
        self._set_text(self.overview_text, "Select Refresh overview to inspect active adapters, gateways, and DNS servers.")

        health = ttk.Frame(network_page, style="Panel.TFrame", padding=(0, 14, 0, 10))
        health.grid(row=2, column=0, sticky="ew")
        ttk.Label(health, text="GATEWAY + DNS HEALTH", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        health_row = ttk.Frame(health, style="Panel.TFrame")
        health_row.pack(fill="x")
        ttk.Label(health_row, text="DNS test host", style="Panel.TLabel").pack(side="left")
        self.dns_test_host_var = tk.StringVar(value="example.com")
        ttk.Entry(health_row, textvariable=self.dns_test_host_var, width=28).pack(side="left", padx=(8, 10))
        self.gateway_dns_button = ttk.Button(health_row, text="Check gateway + DNS", command=self.start_gateway_dns_check)
        self.gateway_dns_button.pack(side="left")

        saved = ttk.Frame(network_page, style="Panel.TFrame", padding=(0, 12, 0, 0))
        saved.grid(row=3, column=0, sticky="ew")
        ttk.Label(saved, text="SAVED TARGETS", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        saved_row = ttk.Frame(saved, style="Panel.TFrame")
        saved_row.pack(fill="x")
        self.saved_target_var = tk.StringVar()
        self.saved_target_combo = ttk.Combobox(saved_row, textvariable=self.saved_target_var, state="readonly", width=38)
        self.saved_target_combo.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.saved_target_combo.bind("<<ComboboxSelected>>", self._select_saved_target)
        ttk.Button(saved_row, text="Save current", command=self.save_current_target).pack(side="left", padx=3)
        ttk.Button(saved_row, text="Remove", command=self.remove_saved_target).pack(side="left", padx=3)

    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _bind_shortcuts(self) -> None:
        self.root.bind_all("<Control-Return>", self._shortcut_test)
        self.root.bind_all("<Control-Shift-M>", self._shortcut_monitor)
        self.root.bind_all("<Control-Shift-E>", self._shortcut_export)
        self.root.bind_all("<Control-Shift-S>", self._shortcut_save_target)
        self.root.bind_all("<Control-Shift-N>", self._shortcut_network_tab)

    def _shortcut_test(self, _event: tk.Event) -> str:
        self.start_test()
        return "break"

    def _shortcut_monitor(self, _event: tk.Event) -> str:
        self.open_monitor()
        return "break"

    def _shortcut_export(self, _event: tk.Event) -> str:
        self.export_report()
        return "break"

    def _shortcut_save_target(self, _event: tk.Event) -> str:
        self.save_current_target()
        return "break"

    def _shortcut_network_tab(self, _event: tk.Event) -> str:
        self.workspace.select(self.network_page)
        return "break"

    def _discover_interfaces(self) -> None:
        try:
            adapters = get_network_adapters()
            error = None
        except Exception as caught_error:
            adapters = []
            error = caught_error
        self._safe_after(self._update_interface_choices, adapters, error)

    def _update_interface_choices(
        self,
        adapters: list[NetworkAdapter],
        error: Exception | None,
    ) -> None:
        choices = ["Default route"]
        self.interface_sources = {"Default route": None}
        for adapter in adapters:
            for address_with_prefix in adapter.ipv4:
                address = address_with_prefix.split("/", 1)[0]
                label = f"{adapter.name}  |  {address}"
                choices.append(label)
                self.interface_sources[label] = address
        self.interface_combo.configure(values=choices)
        monitor_combo = getattr(self, "monitor_interface_combo", None)
        if monitor_combo is not None and monitor_combo.winfo_exists():
            monitor_combo.configure(values=choices)
        selected = next(
            (label for label, address in self.interface_sources.items() if address == self.preferred_source_address),
            "Default route",
        )
        self.interface_var.set(selected)
        if self.monitor_window is not None and self.monitor_window.winfo_exists():
            monitor_source = next(
                (label for label, address in self.interface_sources.items() if address == self.preferred_source_address),
                "Default route",
            )
            self.monitor_source_var.set(monitor_source)
        if adapters:
            self._set_text(self.overview_text, format_network_overview(adapters))
        elif error is not None:
            self._set_text(self.overview_text, f"Adapter discovery unavailable: {error}")

    def _selected_source_address(self, variable: tk.StringVar | None = None) -> str | None:
        selected = (variable or self.interface_var).get()
        return self.interface_sources.get(selected)

    def _refresh_saved_targets(self) -> None:
        self.saved_targets = load_saved_targets()
        labels = [f"{target['name']}  |  {target['host']}:{target['port']}" for target in self.saved_targets]
        self.saved_target_combo.configure(values=labels)
        if labels and self.saved_target_var.get() not in labels:
            self.saved_target_var.set(labels[0])
        elif not labels:
            self.saved_target_var.set("")

    def _select_saved_target(self, _event: tk.Event | None = None) -> None:
        selected = self.saved_target_var.get()
        labels = list(self.saved_target_combo.cget("values"))
        try:
            target = self.saved_targets[labels.index(selected)]
        except (ValueError, IndexError):
            return
        self.host_var.set(str(target["host"]))
        self.port_var.set(str(target["port"]))
        self.count_var.set(int(target.get("ping_count", 4)))
        self.timeout_var.set(int(target.get("timeout_ms", 1000)))
        self.monitor_interval_pref.set(int(target.get("interval_seconds", 1)))
        self.alert_latency_var.set(float(target.get("alert_latency_ms", 150)))
        self.alert_loss_var.set(int(target.get("alert_loss_percent", 10)))
        source = str(target.get("source_address", "")) or None
        self.preferred_source_address = source
        selected_source = next(
            (label for label, address in self.interface_sources.items() if address == source),
            "Default route",
        )
        self.interface_var.set(selected_source)

    def save_current_target(self) -> None:
        host = self.host_var.get().strip()
        if not validate_target(host):
            messagebox.showerror("Invalid target", "Enter a valid IP address or DNS hostname first.", parent=self.root)
            return
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid port", "Saved target port must be between 1 and 65535.", parent=self.root)
            return
        name = simpledialog.askstring("Save target", "Name this target:", initialvalue=host, parent=self.root)
        if not name or not name.strip():
            return
        saved = [target for target in self.saved_targets if target["name"].casefold() != name.strip().casefold()]
        try:
            ping_count = int(self.count_var.get())
            timeout_ms = int(self.timeout_var.get())
            interval = int(self.monitor_interval_pref.get())
            latency_alert = float(self.alert_latency_var.get())
            loss_alert = int(self.alert_loss_var.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid settings", "Check the ping, monitor, and alert settings.", parent=self.root)
            return
        saved.append(
            {
                "name": name.strip(),
                "host": host,
                "port": port,
                "ping_count": ping_count,
                "timeout_ms": timeout_ms,
                "interval_seconds": interval,
                "alert_latency_ms": latency_alert,
                "alert_loss_percent": loss_alert,
                "source_address": self._selected_source_address() or "",
            }
        )
        try:
            save_targets(saved)
        except OSError as error:
            messagebox.showerror("Could not save target", str(error), parent=self.root)
            return
        self._refresh_saved_targets()
        self.saved_target_var.set(f"{name.strip()}  |  {host}:{port}")

    def remove_saved_target(self) -> None:
        selected = self.saved_target_var.get()
        labels = list(self.saved_target_combo.cget("values"))
        try:
            index = labels.index(selected)
        except ValueError:
            return
        saved = [target for position, target in enumerate(self.saved_targets) if position != index]
        try:
            save_targets(saved)
        except OSError as error:
            messagebox.showerror("Could not remove target", str(error), parent=self.root)
            return
        self._refresh_saved_targets()

    def start_network_overview(self) -> None:
        self._start_tool("Local overview", self.overview_button, "Local adapters", get_network_adapters)

    def start_gateway_dns_check(self) -> None:
        dns_host = self.dns_test_host_var.get().strip()
        if not validate_target(dns_host):
            messagebox.showerror("Invalid DNS host", "Enter a valid hostname or IP address.", parent=self.root)
            return
        self._start_tool(
            "Gateway + DNS",
            self.gateway_dns_button,
            dns_host,
            lambda: check_gateway_dns(dns_host),
        )

    def compare_selected_history(self) -> None:
        selected = self.history.selection()
        if len(selected) != 2:
            messagebox.showinfo("Select two results", "Select exactly two history rows to compare.", parent=self.root)
            return
        first, second = sorted(
            (self.history_item_rows[item] for item in selected),
            key=lambda row: row.get("timestamp", ""),
        )
        lines = [
            "DIAGNOSTIC COMPARISON",
            "=" * 22,
            f"Earlier: {first.get('timestamp', '')} | {first.get('test_type', '')} | {first.get('target', '')}",
            f"  Status: {first.get('status', '')}",
            f"  Details: {first.get('details', '')}",
            f"Later:   {second.get('timestamp', '')} | {second.get('test_type', '')} | {second.get('target', '')}",
            f"  Status: {second.get('status', '')}",
            f"  Details: {second.get('details', '')}",
        ]
        first_latency = first.get("average_latency_ms", "")
        second_latency = second.get("average_latency_ms", "")
        try:
            delta = float(second_latency) - float(first_latency)
            lines.append(f"Average latency change: {delta:+.2f} ms")
        except (TypeError, ValueError):
            pass
        first_loss = first.get("packet_loss_percent", "")
        second_loss = second.get("packet_loss_percent", "")
        try:
            delta = float(second_loss) - float(first_loss)
            lines.append(f"Packet loss change: {delta:+.1f} percentage points")
        except (TypeError, ValueError):
            pass
        self._open_result_window("Compare diagnostic results", "\n".join(lines))

    def _start_tool(
        self,
        test_type: str,
        button: ttk.Button,
        host: str,
        action: Callable[[], object],
        port: int | None = None,
    ) -> None:
        button.configure(state="disabled")
        self.progress_var.set(f"Running {test_type.lower()} for {host}...")

        def worker() -> None:
            try:
                value = action()
                error = None
            except Exception as caught_error:
                value = None
                error = caught_error
            self._safe_after(self._finish_tool, test_type, button, host, port, value, error)

        threading.Thread(target=worker, daemon=True).start()

    def start_dns_lookup(self) -> None:
        host = self.host_var.get().strip()
        self._start_tool("DNS lookup", self.dns_button, host, lambda: lookup_dns(host))

    def start_tcp_check(self) -> None:
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid port", str(error), parent=self.root)
            return
        source_address = self._selected_source_address()
        self._start_tool(
            "TCP port",
            self.tcp_button,
            host,
            lambda: check_tcp_port(host, port, source_address=source_address),
            port,
        )

    def start_traceroute(self) -> None:
        host = self.host_var.get().strip()
        try:
            max_hops = int(self.hops_var.get())
            if not 1 <= max_hops <= 30:
                raise ValueError("Maximum hops must be between 1 and 30.")
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid hop limit", str(error), parent=self.root)
            return
        self._start_tool(
            "Traceroute",
            self.trace_button,
            host,
            lambda: run_traceroute(host, max_hops=max_hops),
        )

    def _finish_tool(
        self,
        test_type: str,
        button: ttk.Button,
        host: str,
        port: int | None,
        value: object,
        error: Exception | None,
    ) -> None:
        button.configure(state="normal")
        latency: float | None = None
        if error is not None:
            status = "Error"
            details = str(error)
            report_body = details
        elif test_type == "DNS lookup":
            addresses = cast(list[str], value)
            status = "Resolved"
            details = f"{len(addresses)} address(es) found"
            report_body = "Resolved addresses:\n" + "\n".join(addresses)
        elif test_type == "TCP port":
            tcp_result = cast(TcpResult, value)
            status = "Open" if tcp_result.is_open else "Closed / filtered"
            latency = tcp_result.latency_ms
            details = f"Port {port}: {tcp_result.details}"
            if latency is not None:
                details += f" ({latency:.2f} ms)"
            report_body = details
        elif test_type == "Local overview":
            adapters = cast(list[NetworkAdapter], value)
            report_body = format_network_overview(adapters)
            status = "Overview ready"
            details = f"{len(adapters)} adapter(s)"
            self._update_interface_choices(adapters, None)
        elif test_type == "Gateway + DNS":
            connectivity = cast(ConnectivityResult, value)
            status = connectivity.status
            details = connectivity.details.replace("\n", " | ")
            report_body = connectivity.details
        else:
            status = "Complete"
            report_body = str(value)
            details = report_body.splitlines()[0][:180] if report_body.splitlines() else "Traceroute completed"

        entry = {
            "timestamp": timestamp_now(),
            "test_type": test_type,
            "target": host,
            "status": status,
            "details": details,
            "sent": "",
            "received": "",
            "packet_loss_percent": "",
            "average_latency_ms": latency if latency is not None else "",
            "minimum_latency_ms": "",
            "maximum_latency_ms": "",
            "port": port if port is not None else "",
            "source_address": self._selected_source_address() or "",
        }
        try:
            append_history(entry)
        except OSError as log_error:
            messagebox.showerror("Log write failed", str(log_error), parent=self.root)
        self.latest_report = "\n".join(
            ("NETWORK DIAGNOSTIC REPORT", "=" * 28, f"Timestamp: {entry['timestamp']}",
             f"Test: {test_type}", f"Target: {host}", f"Status: {status}", report_body)
        )
        self.result_status.set(f"{status}  |  {host}")
        self.result_detail.set(details[:180])
        self.progress_var.set(f"{test_type} finished")
        self._load_history()
        self._open_result_window(test_type, report_body)

    def _open_result_window(self, title: str, body: str) -> None:
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("640x420")
        window.minsize(460, 280)
        output = tk.Text(window, wrap="word", font=("Consolas", 10), padx=12, pady=12)
        output.pack(fill="both", expand=True)
        output.insert("1.0", body)
        output.configure(state="disabled")

    def open_monitor(self) -> None:
        if self.monitor_window is not None and self.monitor_window.winfo_exists():
            self.monitor_window.lift()
            return
        window = tk.Toplevel(self.root)
        window.title("Continuous Host Monitor")
        window.geometry("980x680")
        window.minsize(720, 520)
        self.monitor_window = window
        self.monitor_samples = []
        self.session_events = []
        self.monitor_error_active = False
        self.monitor_host_var = tk.StringVar(value=self.host_var.get().strip())
        self.monitor_interval_var = self.monitor_interval_pref
        self.monitor_source_var = tk.StringVar(value=self.interface_var.get())
        self.monitor_latency_threshold_var = self.alert_latency_var
        self.monitor_loss_threshold_var = self.alert_loss_var
        self.monitor_status_var = tk.StringVar(value="Monitoring is stopped")

        controls = ttk.Frame(window, padding=14)
        controls.pack(fill="x")
        ttk.Label(controls, text="Host").pack(side="left")
        ttk.Entry(controls, textvariable=self.monitor_host_var, width=19).pack(side="left", padx=(6, 10))
        ttk.Label(controls, text="Interface").pack(side="left")
        self.monitor_interface_combo = ttk.Combobox(
            controls,
            textvariable=self.monitor_source_var,
            values=self.interface_combo.cget("values"),
            state="readonly",
            width=23,
        )
        self.monitor_interface_combo.pack(side="left", padx=(6, 10))
        ttk.Label(controls, text="Interval (seconds)").pack(side="left")
        ttk.Spinbox(controls, from_=1, to=300, increment=1, textvariable=self.monitor_interval_var, width=5).pack(side="left", padx=6)
        self.monitor_start_button = ttk.Button(controls, text="Start", command=self.start_monitor)
        self.monitor_start_button.pack(side="left", padx=(10, 4))
        self.monitor_stop_button = ttk.Button(controls, text="Stop", command=self.stop_monitor, state="disabled")
        self.monitor_stop_button.pack(side="left")
        alert_controls = ttk.Frame(window, padding=(14, 0, 14, 8))
        alert_controls.pack(fill="x")
        ttk.Label(alert_controls, text="Alert above latency (ms)").pack(side="left")
        ttk.Spinbox(alert_controls, from_=1, to=60000, increment=10, textvariable=self.monitor_latency_threshold_var, width=8).pack(side="left", padx=(6, 16))
        ttk.Label(alert_controls, text="Alert at packet loss (%)").pack(side="left")
        ttk.Spinbox(alert_controls, from_=0, to=100, increment=1, textvariable=self.monitor_loss_threshold_var, width=6).pack(side="left", padx=6)
        ttk.Label(window, textvariable=self.monitor_status_var, padding=(14, 0, 14, 8)).pack(anchor="w")
        self.monitor_canvas = tk.Canvas(window, height=340, bg="#ffffff", highlightthickness=1, highlightbackground="#d7dfdb")
        self.monitor_canvas.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.monitor_canvas.bind("<Configure>", lambda _event: self._draw_monitor_chart())
        events_frame = ttk.Frame(window, padding=(14, 0, 14, 12))
        events_frame.pack(fill="x")
        ttk.Label(events_frame, text="SESSION EVENTS", style="Muted.TLabel").pack(anchor="w", pady=(0, 4))
        self.monitor_event_list = tk.Listbox(events_frame, height=5, font=("Consolas", 9), activestyle="none")
        self.monitor_event_list.pack(fill="x")
        window.protocol("WM_DELETE_WINDOW", self.close_monitor)
        self._draw_monitor_chart()

    def start_monitor(self) -> None:
        host = self.monitor_host_var.get().strip()
        try:
            interval = int(self.monitor_interval_var.get())
            if not validate_target(host):
                raise ValueError("Enter a valid IP address or DNS hostname.")
            if not 1 <= interval <= 300:
                raise ValueError("Monitoring interval must be between 1 and 300 seconds.")
            if float(self.monitor_latency_threshold_var.get()) <= 0:
                raise ValueError("Latency alert threshold must be greater than zero.")
            if not 0 <= int(self.monitor_loss_threshold_var.get()) <= 100:
                raise ValueError("Packet-loss alert threshold must be between 0 and 100 percent.")
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid monitor settings", str(error), parent=self.monitor_window)
            return
        if self.monitor_stop_event is not None and not self.monitor_stop_event.is_set():
            return

        stop_event = threading.Event()
        self.monitor_stop_event = stop_event
        self.monitor_alert_active = False
        self.monitor_error_active = False
        self.monitor_start_button.configure(state="disabled")
        self.monitor_stop_button.configure(state="normal")
        source_address = self._selected_source_address(self.monitor_source_var)
        source_label = f" via {source_address}" if source_address else " via default route"
        self.monitor_status_var.set(f"Monitoring {host}{source_label} every {interval} second(s)")
        self._add_monitor_event(f"Monitoring started: {host}{source_label}, interval {interval}s")

        def monitor_worker() -> None:
            next_probe = time.monotonic()
            while not stop_event.is_set():
                try:
                    result = run_ping(host, count=1, timeout_ms=750, source_address=source_address)
                    self._safe_after(self._record_monitor_sample, result, None)
                except Exception as error:
                    self._safe_after(self._record_monitor_sample, None, error)
                next_probe += interval
                delay = max(0, next_probe - time.monotonic())
                if stop_event.wait(delay):
                    break
            self._safe_after(self._monitor_stopped, stop_event)

        threading.Thread(target=monitor_worker, daemon=True).start()

    def stop_monitor(self) -> None:
        if self.monitor_stop_event is not None:
            self.monitor_stop_event.set()
            self.monitor_status_var.set("Stopping after the current ping...")
            self.monitor_stop_button.configure(state="disabled")

    def close_monitor(self) -> None:
        self.stop_monitor()
        if self.monitor_window is not None:
            self.monitor_window.destroy()
            self.monitor_window = None

    def _monitor_stopped(self, stop_event: threading.Event) -> None:
        if self.monitor_stop_event is stop_event:
            self.monitor_stop_event = None
        if self.monitor_window is not None and self.monitor_window.winfo_exists():
            self._add_monitor_event("Monitoring stopped")
            self.monitor_start_button.configure(state="normal")
            self.monitor_stop_button.configure(state="disabled")
            self.monitor_status_var.set("Monitoring is stopped")

    def _record_monitor_sample(self, result: PingResult | None, error: Exception | None) -> None:
        if result is None:
            if self.monitor_window is not None and self.monitor_window.winfo_exists():
                self.monitor_status_var.set(f"Ping error: {error}")
                if not self.monitor_error_active:
                    self._add_monitor_event(f"Probe error: {error}")
                    self._show_desktop_notification("Network monitor", f"Probe failed: {error}")
                self.monitor_error_active = True
            return
        if self.monitor_error_active:
            self._add_monitor_event("Connectivity check recovered")
            self._show_desktop_notification("Network monitor", "Connectivity check recovered")
        self.monitor_error_active = False
        self.monitor_samples.append(result)
        self.monitor_samples = self.monitor_samples[-60:]
        self.latest_result = result
        self.latest_report = "\n".join(
            (
                "NETWORK DIAGNOSTIC REPORT",
                "=" * 28,
                f"Timestamp: {result.timestamp}",
                "Test: Monitor ping",
                f"Target: {result.host}",
                f"Source interface: {result.source_address or 'Default route'}",
                f"Status: {result.status}",
                f"Packet loss: {result.packet_loss_percent:.1f}%",
                f"Average latency: {format_latency(result.average_latency_ms)}",
            )
        )
        try:
            append_history(ping_history_row(result, "Monitor ping"))
        except OSError as log_error:
            if self.monitor_window is not None and self.monitor_window.winfo_exists():
                self.monitor_status_var.set(f"Could not write history: {log_error}")
        if self.monitor_window is not None and self.monitor_window.winfo_exists():
            alert = self._monitor_alert_message(result)
            if alert and not self.monitor_alert_active:
                self._add_monitor_event(f"Alert: {alert}")
                self._show_desktop_notification("Network monitor alert", alert)
            elif not alert and self.monitor_alert_active:
                self._add_monitor_event("Alert cleared; measurements returned below thresholds")
                self._show_desktop_notification("Network monitor recovered", "Measurements returned below thresholds")
            self.monitor_alert_active = bool(alert)
            prefix = f"ALERT: {alert}  |  " if alert else ""
            self.monitor_status_var.set(
                prefix + f"{result.timestamp}  |  {format_latency(result.average_latency_ms)}  |  "
                f"{result.packet_loss_percent:.0f}% loss"
            )
            self._draw_monitor_chart()
        self._load_history()

    def _add_monitor_event(self, event: str) -> None:
        if self.monitor_window is None or not self.monitor_window.winfo_exists():
            return
        entry = f"{datetime.now():%H:%M:%S}  {event}"
        self.session_events.append(entry)
        self.session_events = self.session_events[-100:]
        self.monitor_event_list.insert("end", entry)
        while self.monitor_event_list.size() > 100:
            self.monitor_event_list.delete(0)
        self.monitor_event_list.see("end")

    def _show_desktop_notification(self, title: str, message: str) -> None:
        self.root.bell()
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        toast.configure(bg="#172321")
        tk.Label(
            toast,
            text=title,
            bg="#172321",
            fg="#ffffff",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).pack(fill="x", padx=14, pady=(10, 3))
        tk.Label(
            toast,
            text=message,
            bg="#172321",
            fg="#d4e2dc",
            font=("Segoe UI", 9),
            justify="left",
            wraplength=340,
        ).pack(fill="x", padx=14, pady=(0, 10))
        toast.update_idletasks()
        x = self.root.winfo_screenwidth() - toast.winfo_width() - 24
        y = self.root.winfo_screenheight() - toast.winfo_height() - 60
        toast.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        toast.after(6500, toast.destroy)

    def _monitor_alert_message(self, result: PingResult) -> str:
        try:
            latency_limit = float(self.monitor_latency_threshold_var.get())
            loss_limit = int(self.monitor_loss_threshold_var.get())
        except (ValueError, tk.TclError):
            return ""
        alerts = []
        if result.average_latency_ms is not None and result.average_latency_ms > latency_limit:
            alerts.append(f"latency exceeded {latency_limit:g} ms")
        if result.packet_loss_percent >= loss_limit and result.packet_loss_percent > 0:
            alerts.append(f"packet loss reached {loss_limit}%")
        return "; ".join(alerts)

    def _draw_monitor_chart(self) -> None:
        canvas = getattr(self, "monitor_canvas", None)
        if canvas is None or not canvas.winfo_exists():
            return
        canvas.delete("all")
        width = max(canvas.winfo_width(), 300)
        height = max(canvas.winfo_height(), 220)
        left, right, top, bottom = 48, width - 18, 28, height - 34
        canvas.create_text(
            left,
            12,
            text="Latency (green, ms)  |  Packet loss (red at baseline)  |  Most recent 60 samples",
            anchor="w",
            fill="#52635d",
            font=("Segoe UI", 9),
        )
        canvas.create_line(left, top, left, bottom, fill="#aebbb5")
        canvas.create_line(left, bottom, right, bottom, fill="#aebbb5")
        samples = self.monitor_samples
        latencies = [sample.average_latency_ms for sample in samples if sample.average_latency_ms is not None]
        if not samples:
            canvas.create_text(width / 2, height / 2, text="Start monitoring to collect samples", fill="#64736f")
            return
        maximum = max(max(latencies, default=0), 1)
        for grid_value in (0, maximum / 2, maximum):
            y = bottom - (grid_value / maximum) * (bottom - top)
            canvas.create_line(left, y, right, y, fill="#e4eae7")
            canvas.create_text(left - 8, y, text=f"{grid_value:.0f}", anchor="e", fill="#64736f", font=("Segoe UI", 8))
        denominator = max(len(samples) - 1, 1)
        points: list[tuple[float, float]] = []
        for index, sample in enumerate(samples):
            x = left + (right - left) * index / denominator
            if sample.average_latency_ms is None:
                canvas.create_oval(x - 4, bottom - 4, x + 4, bottom + 4, fill="#c14d3a", outline="")
                if len(samples) == 1:
                    canvas.create_text(x, bottom - 14, text="100% loss", fill="#a43c2d", font=("Segoe UI", 8))
                points = []
                continue
            y = bottom - (sample.average_latency_ms / maximum) * (bottom - top)
            if points:
                canvas.create_line(*points[-1], x, y, fill="#187653", width=2)
            canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill="#187653", outline="")
            points = [(x, y)]

    def start_test(self) -> None:
        host = self.host_var.get().strip()
        source_address = self._selected_source_address()
        try:
            count = int(self.count_var.get())
            timeout_ms = int(self.timeout_var.get())
            if not 1 <= count <= 20:
                raise ValueError("Packet count must be between 1 and 20.")
            if not 250 <= timeout_ms <= 10000:
                raise ValueError("Timeout must be between 250 and 10000 ms.")
            if not validate_target(host):
                raise ValueError("Enter a valid IP address or DNS hostname.")
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid test settings", str(error), parent=self.root)
            return

        self.run_button.configure(state="disabled")
        interface = f" via {source_address}" if source_address else ""
        self.progress_var.set(f"Pinging {host}{interface}...")
        threading.Thread(
            target=self._run_test,
            args=(host, count, timeout_ms, source_address),
            daemon=True,
        ).start()

    def _run_test(self, host: str, count: int, timeout_ms: int, source_address: str | None) -> None:
        try:
            result = run_ping(host, count, timeout_ms, source_address)
            self._safe_after(self._finish_test, result, None)
        except Exception as error:
            self._safe_after(self._finish_test, None, error)

    def _finish_test(self, result: PingResult | None, error: Exception | None) -> None:
        self.run_button.configure(state="normal")
        if error is not None:
            self.progress_var.set("Test could not be completed")
            messagebox.showerror("Ping failed", str(error), parent=self.root)
            return
        assert result is not None
        self.latest_result = result
        self.latest_report = "\n".join(
            (
                "NETWORK DIAGNOSTIC REPORT",
                "=" * 28,
                f"Timestamp: {result.timestamp}",
                f"Test: Ping",
                f"Target: {result.host}",
                f"Source interface: {result.source_address or 'Default route'}",
                f"Status: {result.status}",
                f"Packets sent: {result.sent}",
                f"Replies received: {result.received}",
                f"Packet loss: {result.packet_loss_percent:.1f}%",
                f"Average latency: {format_latency(result.average_latency_ms)}",
                f"Minimum latency: {format_latency(result.minimum_latency_ms)}",
                f"Maximum latency: {format_latency(result.maximum_latency_ms)}",
            )
        )
        try:
            append_history(ping_history_row(result))
        except OSError as log_error:
            messagebox.showerror("Log write failed", str(log_error), parent=self.root)
        self._show_result(result)
        self._load_history()

    def _show_result(self, result: PingResult) -> None:
        self.progress_var.set(f"Completed at {result.timestamp}")
        source = f" via {result.source_address}" if result.source_address else ""
        self.result_status.set(f"{result.status}  |  {result.host}{source}")
        self.result_detail.set(
            f"{result.received} of {result.sent} replies\n"
            f"Min {format_latency(result.minimum_latency_ms)}  |  Max {format_latency(result.maximum_latency_ms)}"
        )
        self.stat_vars[0].set(format_latency(result.average_latency_ms))
        self.stat_vars[1].set(f"{result.packet_loss_percent:.0f}%")
        self.stat_vars[2].set(f"{result.received} / {result.sent}")

    def _load_history(self) -> None:
        try:
            self.history_rows = load_history()
        except (OSError, csv.Error):
            self.history_rows = []
        self._apply_history_filter()

    def _apply_history_filter(self) -> None:
        if not hasattr(self, "history"):
            return
        for item in self.history.get_children():
            self.history.delete(item)
        self.history_item_rows = {}
        query = self.history_search_var.get().strip().casefold()
        selected_type = self.history_type_var.get()
        matching_rows = [
            row for row in self.history_rows
            if (selected_type == "All types" or row.get("test_type") == selected_type)
            and (not query or query in " ".join(row.values()).casefold())
        ]
        self.visible_history_rows = matching_rows
        for row in matching_rows[:500]:
            latency = row.get("average_latency_ms", "")
            try:
                latency_text = f"{float(latency):.2f} ms" if latency else "N/A"
            except ValueError:
                latency_text = "N/A"
            timestamp = row.get("timestamp", "").replace("T", " ")
            timestamp = timestamp[:19]
            loss = row.get("packet_loss_percent", "")
            try:
                loss_text = f"{float(loss):.0f}%" if loss != "" else "-"
            except ValueError:
                loss_text = "-"
            details = row.get("details", "").replace("\n", " ")
            item = self.history.insert(
                "",
                "end",
                values=(
                    timestamp,
                    row.get("test_type", ""),
                    row.get("target", ""),
                    row.get("status", ""),
                    details[:180],
                    latency_text,
                    loss_text,
                ),
            )
            self.history_item_rows[item] = row

    def export_report(self) -> None:
        report = self.latest_report
        if report is None:
            messagebox.showinfo("No diagnostic yet", "Run a ping test before exporting a report.", parent=self.root)
            return
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save diagnostic report",
            defaultextension=".txt",
            initialfile=f"network-report-{datetime.now():%Y%m%d-%H%M%S}.txt",
            filetypes=(("Text report", "*.txt"), ("All files", "*.*")),
        )
        if not destination:
            return
        try:
            Path(destination).write_text(report, encoding="utf-8")
        except OSError as error:
            messagebox.showerror("Report export failed", str(error), parent=self.root)
            return
        self.progress_var.set(f"Report saved to {Path(destination).name}")

    def export_history(self) -> None:
        if not self.visible_history_rows:
            messagebox.showinfo("No history to export", "There are no rows matching the current history filter.", parent=self.root)
            return
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export diagnostic history",
            defaultextension=".csv",
            initialfile=f"network-history-{datetime.now():%Y%m%d-%H%M%S}.csv",
            filetypes=(("CSV file", "*.csv"), ("All files", "*.*")),
        )
        if not destination:
            return
        try:
            with Path(destination).open("w", newline="", encoding="utf-8") as output_file:
                writer = csv.DictWriter(output_file, fieldnames=HISTORY_FIELDS, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(self.visible_history_rows)
        except OSError as error:
            messagebox.showerror("History export failed", str(error), parent=self.root)
            return
        self.progress_var.set(f"History exported to {Path(destination).name}")


def main() -> None:
    root = tk.Tk()
    NetworkDiagnosticApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
