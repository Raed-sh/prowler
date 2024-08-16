from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
class ec2_securitygroup_exposes_ports_80_443_only(Check):
    def execute(self):
        findings = []
        allowed_ports = [80, 443]

        for security_group_arn, security_group in ec2_client.security_groups.items():
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_details = security_group.name
            report.resource_id = security_group.id
            report.resource_arn = security_group_arn
            report.resource_tags = security_group.tags
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) exposes only ports 80 and 443 to the public internet."

            # Iterate through each ingress rule
            for ingress_rule in security_group.ingress_rules:
                protocol = ingress_rule["IpProtocol"]

                # Check if the protocol is not ICMP
                if protocol.lower() != "icmp":
                    # This should fail if the port is not 80 or 443
                    if check_security_group(ingress_rule, protocol, ports=None, any_address=True):
                        for port in range(ingress_rule["FromPort"], ingress_rule["ToPort"] + 1):
                            if port not in allowed_ports:
                                report.status = "FAIL"
                                report.status_extended = f"Security group {security_group.name} ({security_group.id}) exposes port {port} to the public internet."
                                break

            findings.append(report)

        return findings
