from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_subnet_flow_logs_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for subnet in compute_client.subnets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=subnet)
            report.status = "PASS"
            report.status_extended = f"Subnet {subnet.name} in network {subnet.network} has flow logs enabled."
            if not subnet.flow_logs:
                report.status = "FAIL"
                report.status_extended = f"Subnet {subnet.name} in network {subnet.network} does not have flow logs enabled."
            findings.append(report)

        return findings
