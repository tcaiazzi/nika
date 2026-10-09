"""IPFIX flow export for the ISP NetFlow lab: pmacct probes and nfdump collector."""

from __future__ import annotations

import time
from typing import Any

from nika.runtime.base import LabRuntime
from nika.net_env.verify import exec_or_empty

FLOW_COLLECTOR = "flow_collector"
FLOW_EXPORT_DOMAIN = "flow_export"
FLOW_EXPORT_PREFIXLEN = 24
FLOW_EXPORT_SUBNET = "172.31.0"
FLOW_COLLECTOR_ADDRESS = f"{FLOW_EXPORT_SUBNET}.250"
IPFIX_PORT = 9995
FLOW_DIR = "/var/lib/nika/flows"
FLOW_EXPORTERS_FILE = "/var/lib/nika/flow_exporters"
# nfcapd rotation period; nfdump reads closed files, so this bounds query lag.
FLOW_ROTATE_SEC = 10
# pmacct nfprobe timeouts: export active flows every 10 s, idle flows after 10 s,
# and check for expired flows every 2 s.
NFPROBE_TIMEOUTS = (
    "general=10:maxlife=10:udp=10:icmp=10:tcp=10:tcp.fin=5:tcp.rst=5:expint=2"
)

PMACCT_DIR = "/etc/pmacct"
PMACCT_CONF = f"{PMACCT_DIR}/nika-netflow.conf"
PMACCT_MAP = f"{PMACCT_DIR}/nika-interfaces.map"
PMACCT_SCRIPT = f"{PMACCT_DIR}/nika-netflow.sh"

# Background SNDlib demand traffic: about 30 Mbps in total on Abilene.
TRAFFIC_SCALE = 0.01
TRAFFIC_UNIT = "K"
TRAFFIC_DURATION_SEC = 7200
TRAFFIC_BASE_PORT = 5201
BASELINE_MIN_SEC = 60
BASELINE_MAX_WAIT_SEC = 180


def export_addresses(routers: list[str]) -> dict[str, str]:
    """Export-LAN address of each router, in name order."""
    return {
        router: f"{FLOW_EXPORT_SUBNET}.{index}"
        for index, router in enumerate(sorted(routers), start=1)
    }


def pmacct_conf() -> str:
    return "\n".join(
        [
            "daemonize: false",
            "pcap_ifindex: map",
            f"pcap_interfaces_map: {PMACCT_MAP}",
            "pcap_filter: ip",
            "plugins: nfprobe",
            f"nfprobe_receiver: {FLOW_COLLECTOR_ADDRESS}:{IPFIX_PORT}",
            "nfprobe_version: 10",
            f"nfprobe_timeouts: {NFPROBE_TIMEOUTS}",
            "aggregate: src_host,dst_host,src_port,dst_port,proto,tos,in_iface",
            "",
        ]
    )


def router_export_script(
    *, data_ifaces: list[str], export_iface: str, address: str
) -> str:
    """Configure the export interface, then run an ingress-only IPFIX probe."""
    ifaces = " ".join(data_ifaces)
    return "\n".join(
        [
            "#!/bin/sh",
            # The export LAN is attached after the planned links; retry until it is up.
            'i=0; while [ "$i" -lt 60 ]; do '
            f"ip link set {export_iface} up && "
            f"ip addr replace {address}/{FLOW_EXPORT_PREFIXLEN} dev {export_iface} "
            "&& break; i=$((i+1)); sleep 1; done",
            f": > {PMACCT_MAP}",
            f"for intf in {ifaces}; do",
            '  while [ ! -e "/sys/class/net/$intf/ifindex" ]; do sleep 1; done',
            '  echo "ifindex=$(cat /sys/class/net/$intf/ifindex) ifname=$intf '
            f'direction=in" >> {PMACCT_MAP}',
            "done",
            # Restart the probe if it exits (e.g. after an interface flap).
            f"while true; do pmacctd -f {PMACCT_CONF}; sleep 2; done",
            "",
        ]
    )


def router_startup_line() -> str:
    return f"nohup sh {PMACCT_SCRIPT} >/var/log/nika-netflow.log 2>&1 &"


def collector_startup() -> list[str]:
    return [
        f"ip addr add {FLOW_COLLECTOR_ADDRESS}/{FLOW_EXPORT_PREFIXLEN} dev eth0",
        "ip link set eth0 up",
        f"mkdir -p {FLOW_DIR}",
        f"nfcapd -D -w {FLOW_DIR} -t {FLOW_ROTATE_SEC} -p {IPFIX_PORT} "
        "-P /run/nfcapd.pid",
    ]


def exporters_file(addresses: dict[str, str]) -> str:
    return "".join(f"{address} {router}\n" for router, address in addresses.items())


def flow_export_running(runtime: LabRuntime, routers: list[str]) -> bool:
    """The collector and every router probe are running."""
    if "nfcapd" not in exec_or_empty(runtime, FLOW_COLLECTOR, "pgrep -a nfcapd"):
        return False
    return all(
        "pmacctd" in exec_or_empty(runtime, router, "pgrep -a pmacctd")
        for router in routers
    )


def seen_exporters(runtime: LabRuntime) -> set[str]:
    out = exec_or_empty(
        runtime,
        FLOW_COLLECTOR,
        f"TZ=UTC nfdump -R {FLOW_DIR} -q -N -A router -o 'fmt:%ra'",
        timeout=20,
    )
    return {line.strip() for line in out.splitlines() if line.strip()}


def wait_for_flow_baseline(
    runtime: LabRuntime,
    exporter_ips: set[str],
    *,
    min_sec: float = BASELINE_MIN_SEC,
    max_wait_sec: float = BASELINE_MAX_WAIT_SEC,
) -> dict[str, Any]:
    """Wait until every router has exported flows and ``min_sec`` has elapsed."""
    started = time.monotonic()
    seen: set[str] = set()
    while True:
        elapsed = time.monotonic() - started
        seen = seen_exporters(runtime)
        if exporter_ips <= seen and elapsed >= min_sec:
            break
        if elapsed >= max_wait_sec:
            break
        time.sleep(10)
    return {
        "exporters_seen": len(exporter_ips & seen),
        "exporters_expected": len(exporter_ips),
        "waited_sec": round(time.monotonic() - started, 1),
    }


def start_background_traffic(
    runtime: LabRuntime,
    *,
    topo: str,
    inventory: dict[str, Any],
    scale: float = TRAFFIC_SCALE,
    duration_sec: int = TRAFFIC_DURATION_SEC,
) -> dict[str, Any]:
    """Start the SNDlib demand matrix as long-running UDP iperf3 flows.

    One iperf3 server per OD pair listens on the destination stub; every
    client runs detached so the call returns once all flows are started.
    """
    from nika.net_env.isp.traffic import resolve_traffic_series
    from nika.net_env.isp.traffic.od import series_to_od_dicts
    from nika.traffic.sndlib_replay import host_ips_from_isp_inventory

    series = resolve_traffic_series(topo, "demands")
    if series is None:
        raise RuntimeError(f"No SNDlib demand series for topology {topo!r}")
    od = series_to_od_dicts(series, scale=scale, inventory=inventory)[0]
    host_ips = host_ips_from_isp_inventory(inventory)

    server_ports: dict[str, list[int]] = {}
    client_cmds: dict[str, list[str]] = {}
    for src, dests in sorted(od.items()):
        for dst, volume in sorted(dests.items()):
            if src == dst or volume <= 0:
                continue
            ports = server_ports.setdefault(dst, [])
            port = TRAFFIC_BASE_PORT + len(ports)
            ports.append(port)
            client_cmds.setdefault(src, []).append(
                f"nohup iperf3 -c {host_ips[dst]} -p {port} -u "
                f"-b {volume}{TRAFFIC_UNIT} -t {duration_sec} >/dev/null 2>&1 &"
            )

    for host in sorted(set(server_ports) | set(client_cmds)):
        servers = " ; ".join(f"iperf3 -s -D -p {p}" for p in server_ports.get(host, []))
        runtime.exec(host, f"pkill -x iperf3 ; {servers or 'true'}", timeout=20)
    for host, cmds in sorted(client_cmds.items()):
        runtime.exec(host, " ".join(cmds), timeout=20)
    return {
        "source": "sndlib_demands",
        "scale": scale,
        "unit": TRAFFIC_UNIT,
        "duration_sec": duration_sec,
        "flow_pairs": sum(len(cmds) for cmds in client_cmds.values()),
        "started_at": time.time(),
    }
