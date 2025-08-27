from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import cloudwatch_client
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client

class cloudwatch_alarm_for_dynamodb_write_capacity(Check):
    def execute(self):
        findings = []

        # Define the expected metric name and namespace for DynamoDB write capacity
        expected_metric_name = 'ConsumedWriteCapacityUnits'
        expected_namespace = 'AWS/DynamoDB'

        # Fetch all DynamoDB tables
        dynamodb_tables = dynamodb_client.tables

        # Initialize a report for each table
        for table in dynamodb_tables:
            report = Check_Report_AWS(self.metadata())
            report.region = table.region
            report.resource_id = table.name
            report.resource_arn = table.arn
            report.resource_tags = table.tags
            
            # Check if any alarm is configured for DynamoDB write capacity changes for the current table
            alarms_found = any(
                alarm.metric == expected_metric_name and alarm.name_space == expected_namespace
                for alarm in cloudwatch_client.metric_alarms
            )

            if alarms_found:
                report.status = "PASS"
                report.status_extended = f"CloudWatch alarm(s) found for DynamoDB table '{table.name}' write capacity changes."
            else:
                report.status = "FAIL"
                report.status_extended = f"No CloudWatch alarms found for DynamoDB table '{table.name}' write capacity changes."

            findings.append(report)

        return findings
