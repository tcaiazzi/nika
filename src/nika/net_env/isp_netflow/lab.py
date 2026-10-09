"""Abilene ISP lab with IPFIX flow export to a central nfdump collector."""

from __future__ import annotations

from nika.net_env.isp.kathara.lab import Isp
from nika.net_env.isp_netflow.netflow import (
    FLOW_COLLECTOR,
    FLOW_EXPORT_DOMAIN,
    FLOW_EXPORTERS_FILE,
    PMACCT_CONF,
    PMACCT_SCRIPT,
    collector_startup,
    export_addresses,
    exporters_file,
    flow_export_running,
    pmacct_conf,
    router_export_script,
    router_startup_line,
    start_background_traffic,
    wait_for_flow_baseline,
)
from nika.net_env.utils.kathara.docker_files.docker_images import nika_image
from nika.runtime.spec import NodeRole


class IspAbileneNetflow(Isp):
    """Abilene IS-IS lab whose routers export ingress flows over IPFIX."""

    LAB_NAME = "isp_abilene_netflow"
    TOPOLOGY = "abilene"

    def __init__(self, **kwargs) -> None:
        for key in (
            "topo",
            "topo_size",
            "igp",
            "bgp_mode",
            "rpki",
            "rtbh",
            "size",
            "scenario_id",
        ):
            kwargs.pop(key, None)
        super().__init__(
            topo=self.TOPOLOGY,
            igp="isis",
            bgp_mode="none",
            rpki=False,
            rtbh=False,
            scenario_id=self.LAB_NAME,
            **kwargs,
        )
        self.name = self.LAB_NAME
        self.flow_exporters = export_addresses(
            [node.device_name for node in self.plan.nodes]
        )
        self._export_endpoints: set[str] = set()
        self._attach_flow_export()
        self.load_machines()
        # The brief stays the same whether or not the flow tool is mounted;
        # the tool description tells the agent about flow records.
        self.desc = (
            f"{self.desc} Edge stubs carry the SNDlib demand matrix as "
            "background traffic."
        )

    def _attach_flow_export(self) -> None:
        collector = self.lab.new_machine(
            FLOW_COLLECTOR,
            **{"image": nika_image("flow-collector"), "cpus": 0.5, "mem": "256m"},
        )
        self.declare_machine(
            FLOW_COLLECTOR,
            role=NodeRole.INFRASTRUCTURE,
            capabilities=("linux", "netflow"),
        )
        self.lab.connect_machine_to_link(FLOW_COLLECTOR, FLOW_EXPORT_DOMAIN)
        collector.create_file_from_string(
            exporters_file(self.flow_exporters), FLOW_EXPORTERS_FILE
        )
        self.lab.create_file_from_list(collector_startup(), f"{FLOW_COLLECTOR}.startup")

        for node in self.plan.nodes:
            machine = self.lab.machines[node.device_name]
            machine.add_meta("image", nika_image("frr-netflow"))
            # Kathara numbers interfaces in connect order: the planned backbone
            # and edge links come first, so the export LAN is the next one.
            export_iface = f"eth{len(node.interfaces)}"
            self._export_endpoints.add(f"{node.device_name}:{export_iface}")
            self.lab.connect_machine_to_link(node.device_name, FLOW_EXPORT_DOMAIN)
            machine.create_file_from_string(pmacct_conf(), PMACCT_CONF)
            machine.create_file_from_string(
                router_export_script(
                    data_ifaces=[iface.name for iface in node.interfaces],
                    export_iface=export_iface,
                    address=self.flow_exporters[node.device_name],
                ),
                PMACCT_SCRIPT,
            )
            self.lab.fs.appendtext(
                f"{node.device_name}.startup", router_startup_line() + "\n"
            )

    def get_topology(self) -> list:
        # The shared export LAN is not a router-to-router link; listing its
        # first two members would show a link that does not exist.
        return [
            (a, b)
            for a, b in super().get_topology()
            if a not in self._export_endpoints and b not in self._export_endpoints
        ]

    def _with_flow_check(self, result: dict) -> dict:
        ok = flow_export_running(self._build_runtime(), sorted(self.flow_exporters))
        result["checks"]["flow_export_running"] = ok
        result["verified"] = bool(result["verified"]) and ok
        return result

    def startup_verify_lab(self) -> dict:
        return self._with_flow_check(super().startup_verify_lab())

    def verify_lab(self) -> dict:
        return self._with_flow_check(super().verify_lab())

    def post_deploy(self) -> None:
        runtime = self._build_runtime()
        traffic = start_background_traffic(
            runtime, topo=self.TOPOLOGY, inventory=self.inventory
        )
        baseline = wait_for_flow_baseline(runtime, set(self.flow_exporters.values()))
        self.metadata["background_traffic"] = {**traffic, "flow_baseline": baseline}
