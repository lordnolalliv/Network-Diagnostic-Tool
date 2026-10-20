import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import network_diagnostic as diagnostic


class TargetValidationTests(unittest.TestCase):
    def test_accepts_ip_addresses_and_dns_names(self):
        for target in ("192.0.2.1", "2001:db8::1", "example.com", "localhost"):
            with self.subTest(target=target):
                self.assertTrue(diagnostic.validate_target(target))

    def test_rejects_empty_and_command_like_targets(self):
        for target in ("", "   ", "-n 10", "bad name", "example..com", "-example.com"):
            with self.subTest(target=target):
                self.assertFalse(diagnostic.validate_target(target))


class PingParsingTests(unittest.TestCase):
    def test_parses_windows_and_unix_reply_times(self):
        output = "Reply from 192.0.2.1: bytes=32 time=14ms TTL=57\n64 bytes from host: time=0.043 ms"
        self.assertEqual(diagnostic.parse_ping_output(output), [14.0, 0.043])

    def test_parses_sub_millisecond_windows_reply(self):
        self.assertEqual(diagnostic.parse_ping_output("Reply from 192.0.2.1: time<1ms"), [0.5])

    def test_ignores_timeout_lines(self):
        self.assertEqual(diagnostic.parse_ping_output("Request timed out.\n100% packet loss"), [])


class RunPingTests(unittest.TestCase):
    @patch.object(diagnostic.platform, "system", return_value="Windows")
    @patch.object(diagnostic.subprocess, "run")
    def test_reports_latency_and_packet_loss(self, mock_run, _mock_system):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ping"],
            returncode=1,
            stdout="Reply from 192.0.2.1: bytes=32 time=10ms TTL=57\nRequest timed out.",
            stderr="",
        )

        result = diagnostic.run_ping("192.0.2.1", count=2, timeout_ms=1000)

        self.assertEqual(result.status, "Online")
        self.assertEqual(result.sent, 2)
        self.assertEqual(result.received, 1)
        self.assertEqual(result.packet_loss_percent, 50)
        self.assertEqual(result.average_latency_ms, 10)
        mock_run.assert_called_once()
        self.assertEqual(mock_run.call_args.args[0], ["ping", "-n", "2", "-w", "1000", "192.0.2.1"])

    @patch.object(diagnostic.platform, "system", return_value="Windows")
    @patch.object(diagnostic.subprocess, "run")
    def test_reports_no_reply_when_all_packets_time_out(self, mock_run, _mock_system):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ping"], returncode=1, stdout="Request timed out.", stderr=""
        )

        result = diagnostic.run_ping("example.com", count=3, timeout_ms=1000)

        self.assertEqual(result.status, "No reply")
        self.assertEqual(result.received, 0)
        self.assertEqual(result.packet_loss_percent, 100)
        self.assertIsNone(result.average_latency_ms)

    def test_rejects_invalid_target_before_running_ping(self):
        with self.assertRaises(ValueError):
            diagnostic.run_ping("-n 10", count=4, timeout_ms=1000)

    @patch.object(diagnostic.platform, "system", return_value="Windows")
    @patch.object(diagnostic.subprocess, "run")
    def test_binds_ping_to_selected_source_address(self, mock_run, _mock_system):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ping"], returncode=0, stdout="Reply from 192.0.2.1: time=10ms", stderr=""
        )

        result = diagnostic.run_ping("192.0.2.1", count=1, timeout_ms=1000, source_address="192.0.2.20")

        self.assertEqual(result.source_address, "192.0.2.20")
        self.assertEqual(
            mock_run.call_args.args[0],
            ["ping", "-S", "192.0.2.20", "-n", "1", "-w", "1000", "192.0.2.1"],
        )


class AdditionalDiagnosticTests(unittest.TestCase):
    @patch.object(diagnostic.socket, "getaddrinfo")
    def test_dns_lookup_returns_unique_sorted_addresses(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (None, None, None, None, ("192.0.2.10", 0)),
            (None, None, None, None, ("2001:db8::10", 0)),
            (None, None, None, None, ("192.0.2.10", 0)),
        ]

        self.assertEqual(diagnostic.lookup_dns("example.com"), ["192.0.2.10", "2001:db8::10"])
        mock_getaddrinfo.assert_called_once_with("example.com", None, type=diagnostic.socket.SOCK_STREAM)

    @patch.object(diagnostic.time, "perf_counter", side_effect=(1.0, 1.025))
    @patch.object(diagnostic.socket, "create_connection")
    def test_tcp_check_reports_open_port_and_latency(self, mock_connect, _mock_clock):
        result = diagnostic.check_tcp_port("example.com", 443)

        self.assertTrue(result.is_open)
        self.assertAlmostEqual(result.latency_ms, 25)
        mock_connect.assert_called_once_with(("example.com", 443), timeout=3.0)

    @patch.object(diagnostic.socket, "create_connection", side_effect=ConnectionRefusedError("refused"))
    def test_tcp_check_reports_closed_port(self, _mock_connect):
        result = diagnostic.check_tcp_port("127.0.0.1", 443)

        self.assertFalse(result.is_open)
        self.assertIn("refused", result.details)

    def test_tcp_check_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            diagnostic.check_tcp_port("example.com", 65536)

    @patch.object(diagnostic.socket, "create_connection")
    def test_tcp_check_binds_to_selected_source_address(self, mock_connect):
        result = diagnostic.check_tcp_port("example.com", 443, source_address="192.0.2.20")

        self.assertTrue(result.is_open)
        mock_connect.assert_called_once_with(
            ("example.com", 443), timeout=3.0, source_address=("192.0.2.20", 0)
        )

    @patch.object(diagnostic.platform, "system", return_value="Windows")
    @patch.object(diagnostic.shutil, "which", return_value="C:\\Windows\\System32\\tracert.exe")
    @patch.object(diagnostic.subprocess, "run")
    def test_traceroute_uses_bounded_windows_command(self, mock_run, _mock_which, _mock_system):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["tracert"], returncode=0, stdout="Tracing route to example.com", stderr=""
        )

        output = diagnostic.run_traceroute("example.com", max_hops=12, timeout_ms=750)

        self.assertEqual(output, "Tracing route to example.com")
        self.assertEqual(
            mock_run.call_args.args[0],
            ["tracert", "-d", "-h", "12", "-w", "750", "example.com"],
        )


class HistoryTests(unittest.TestCase):
    def test_load_history_includes_legacy_ping_log(self):
        with tempfile.TemporaryDirectory() as directory:
            current_path = Path(directory) / "history.csv"
            legacy_path = Path(directory) / "network_test_log.csv"
            legacy_path.write_text(
                "timestamp,host,status,sent,received,packet_loss_percent,average_latency_ms,minimum_latency_ms,maximum_latency_ms\n"
                "2026-10-20T12:00:00+00:00,example.com,Online,4,4,0,12.5,10,15\n",
                encoding="utf-8",
            )
            with patch.object(diagnostic, "LOG_PATH", current_path), patch.object(
                diagnostic, "LEGACY_LOG_PATH", legacy_path
            ):
                rows = diagnostic.load_history()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["test_type"], "Ping")
        self.assertEqual(rows[0]["target"], "example.com")
        self.assertEqual(rows[0]["details"], "4/4 replies")


class LocalNetworkTests(unittest.TestCase):
    @patch.object(diagnostic.shutil, "which", return_value="powershell.exe")
    @patch.object(diagnostic.platform, "system", return_value="Windows")
    @patch.object(diagnostic.subprocess, "run")
    def test_reads_windows_adapter_configuration(self, mock_run, _mock_system, _mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["powershell"],
            returncode=0,
            stdout=(
                '[{"Name":"Ethernet","IPv4":["192.0.2.20/24"],'
                '"Gateways":["192.0.2.1"],"DNS":["192.0.2.53"]}]'
            ),
            stderr="",
        )

        adapters = diagnostic.get_network_adapters()

        self.assertEqual(len(adapters), 1)
        self.assertEqual(adapters[0].name, "Ethernet")
        self.assertEqual(adapters[0].ipv4, ("192.0.2.20/24",))
        self.assertEqual(adapters[0].gateways, ("192.0.2.1",))
        self.assertEqual(adapters[0].dns_servers, ("192.0.2.53",))

    @patch.object(diagnostic, "get_network_adapters")
    @patch.object(diagnostic, "run_ping")
    @patch.object(diagnostic, "lookup_dns", return_value=["192.0.2.80"])
    def test_gateway_dns_check_reports_both_results(self, _mock_dns, mock_ping, mock_adapters):
        mock_adapters.return_value = [
            diagnostic.NetworkAdapter("Ethernet", ("192.0.2.20/24",), ("192.0.2.1",), ("192.0.2.53",))
        ]
        mock_ping.return_value = diagnostic.PingResult(
            diagnostic.timestamp_now(), "192.0.2.1", "Online", 1, 1, 0, 1.2, 1.2, 1.2
        )

        result = diagnostic.check_gateway_dns("example.com")

        self.assertEqual(result.status, "Passed")
        self.assertIn("192.0.2.1: Online", result.details)
        self.assertIn("192.0.2.80", result.details)

    def test_saved_targets_round_trip(self):
        targets = [
            {
                "name": "Web server",
                "host": "example.com",
                "port": 443,
                "ping_count": 6,
                "timeout_ms": 1500,
                "interval_seconds": 2,
                "alert_latency_ms": 180.0,
                "alert_loss_percent": 15,
                "source_address": "192.0.2.20",
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved_targets.json"
            with patch.object(diagnostic, "TARGETS_PATH", path):
                diagnostic.save_targets(targets)
                loaded = diagnostic.load_saved_targets()

        self.assertEqual(loaded, targets)


if __name__ == "__main__":
    unittest.main()
