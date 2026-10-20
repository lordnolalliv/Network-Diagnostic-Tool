# Network Diagnostic Tool

A lightweight desktop utility for common, single-host network troubleshooting. It checks reachability and latency with `ping`, resolves DNS, checks one TCP port, runs a traceroute, and can continuously monitor a host. Results are searchable in the app, stored in a CSV history, and exportable as CSV or a text report.

## Requirements

- Python 3.10 or newer
- Tkinter (usually included with Python)
- The system `ping` command available on `PATH`
- `tracert` on Windows or `traceroute` on macOS/Linux to use the route trace check

There are no third-party Python dependencies.

## Run

From this folder, run:

```powershell
python network_diagnostic.py
```

Enter one IP address or DNS hostname in the **Host or IP address** field.

- **Run diagnostic** sends 1 to 20 pings and reports replies, latency, and loss.
- **DNS lookup** shows the addresses returned for the entered name.
- **Check TCP port** makes one TCP connection attempt to the selected port. It does not scan port ranges.
- **Network interface** can bind ping, TCP, and monitoring probes to a selected local IPv4 address instead of the default route. The interface list refreshes from active adapters at startup and in the Network overview.
- **Run traceroute** traces one route, with a configurable maximum of 30 hops.
- **Continuous monitor** pings one host in real time at intervals of 1 to 300 seconds. Set latency and packet-loss alert thresholds in its window; threshold crossings, probe failures, and recovery create session events and a short desktop toast with an audible alert. Stop monitoring from that window. The chart keeps the latest 60 samples; missed replies are shown at the baseline in red.
- **Network** shows local adapter IPv4 addresses, default gateways, and DNS servers. **Check gateway + DNS** pings the detected default gateway and resolves the entered DNS test host.
- **Saved targets** stores named host/port pairs plus ping, monitor, alert, and interface settings in `saved_targets.json` for quick reuse.
- **TEST HISTORY** can be searched and filtered by test type. Select two rows and use **Compare 2** to view status, latency, and packet-loss changes. **Export CSV** saves the rows matching the current filter.
- **Export diagnostic report** saves the latest ping, monitor sample, DNS, TCP, or traceroute result as text.

New results are saved to `network_diagnostic_history.csv` next to the script. Existing results in `network_test_log.csv` remain intact and are included in the history view.

On Windows, local adapter information is read with PowerShell's `Get-NetIPConfiguration`. On Linux, the `ip` command is required. Gateway checks depend on the local network allowing ICMP echo replies.

Keyboard shortcuts: `Ctrl+Enter` runs a ping, `Ctrl+Shift+M` opens the monitor, `Ctrl+Shift+E` exports the latest report, `Ctrl+Shift+S` saves the current target and its settings, and `Ctrl+Shift+N` opens the Network tab.

## Tests

Run the offline unit tests with:

```powershell
python -m unittest discover -s tests -v
```

The tests mock network operations, so they do not require a network connection.
