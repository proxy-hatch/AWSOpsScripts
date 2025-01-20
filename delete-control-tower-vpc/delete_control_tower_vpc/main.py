import boto3
import logging
import sys
import argparse
from typing import Dict, List, Any

logger = logging.getLogger()

logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
ROLE_NAME = "AWSControlTowerExecution"
LANDING_ZONE_CREDS = {
    # DO NOT COMMIT YOUR AKSK!
    "aws_access_key_id": "YOUR_ACCESS_KEY_ID",
    "aws_secret_access_key": "YOUR_ACCESS_KEY_SECRET"
}


def assume_role(account_id: str, role_name: str) -> Dict[str, str]:
    """
    Assume a role in the target account using AWS STS.

    Args:
        account_id (str): AWS account ID.
        role_name (str): Role name to assume.

    Returns:
        Dict[str, str]: Temporary credentials.
    """
    sts_client = boto3.client("sts", **LANDING_ZONE_CREDS)
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    logger.debug(f"Assuming role: {role_arn}")
    response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="ControlTowerCleanupSession")
    logger.debug(f"Successfully assumed role for account {account_id}")
    return response["Credentials"]


def get_current_account_id() -> str:
    """
    Retrieve the account ID associated with the provided credentials.

    Returns:
        str: Current AWS account ID.
    """
    sts_client = boto3.client("sts", **LANDING_ZONE_CREDS)
    response = sts_client.get_caller_identity()
    account_id = response["Account"]
    logger.debug(f"Using Access Key/Secret Key associated with account ID (Landing Zone): {account_id}")
    return account_id


def get_all_accounts() -> List[str]:
    """
    Retrieve all active AWS accounts in the organization.

    Returns:
        List[str]: List of active AWS account IDs.
    """
    org_client = boto3.client("organizations", **LANDING_ZONE_CREDS)
    accounts = []
    paginator = org_client.get_paginator("list_accounts")
    for page in paginator.paginate():
        active_accounts = [acct["Id"] for acct in page["Accounts"] if acct["Status"] == "ACTIVE"]
        accounts.extend(active_accounts)
    logger.debug(f"Found accounts in Organization: {accounts}")
    return accounts


def get_vpc_in_all_regions(account_session: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Find all VPCs named 'aws-controltower-VPC' across all AWS regions.

    Args:
        account_session (Dict[str, str]): AWS session credentials for the target account.

    Returns:
        List[Dict[str, str]]: List of VPCs with region and VPC ID.
    """
    ec2_client = boto3.client("ec2", **account_session)
    regions = [region["RegionName"] for region in ec2_client.describe_regions()["Regions"]]
    logger.debug(f"Checking regions: {regions}")
    vpcs = []
    for region in regions:
        regional_ec2 = boto3.client("ec2", region_name=region, **account_session)
        response = regional_ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": ["aws-controltower-VPC"]}])
        for vpc in response["Vpcs"]:
            vpc_info = {"Region": region, "VpcId": vpc["VpcId"]}
            vpcs.append(vpc_info)
            logger.debug(f"Found VPC: {vpc_info}")
    return vpcs


def remove_nat_gateways(account_session: Dict[str, str], vpc: Dict[str, str], dry_run: bool) -> None:
    """
    Remove all NAT Gateways in a specified VPC.

    Args:
        account_session (Dict[str, str]): AWS session credentials for the target account.
        vpc (Dict[str, str]): VPC information with region and VPC ID.
    """
    regional_ec2 = boto3.client("ec2", region_name=vpc["Region"], **account_session)
    response = regional_ec2.describe_nat_gateways(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}])
    for nat_gw in response["NatGateways"]:
        logger.debug(f"Deleting NAT Gateway {nat_gw['NatGatewayId']} in {vpc['Region']}")
        if "NatGatewayId" in nat_gw:
            if not dry_run:
                regional_ec2.delete_nat_gateway(NatGatewayId=nat_gw["NatGatewayId"])
                logger.info(f"Successfully deleted NAT Gateway {nat_gw['NatGatewayId']} in {vpc['Region']}")
            else:
                logger.info(f"Dry-run enabled: did not delete NAT Gateway '{nat_gw["NatGatewayId"]}'")


def remove_flow_logs(account_session: Dict[str, str], vpc: Dict[str, str], dry_run: bool) -> None:
    """
    Remove VPC Flow Logs and their destinations.

    Args:
        account_session (Dict[str, str]): AWS session credentials for the target account.
        vpc (Dict[str, str]): VPC information with region and VPC ID.
    """
    regional_ec2 = boto3.client("ec2", region_name=vpc["Region"], **account_session)
    response = regional_ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}])
    for flow_log in response["FlowLogs"]:
        logger.debug(f"Deleting flow log {flow_log['FlowLogId']} in {vpc['Region']}")
        if not dry_run:
            regional_ec2.delete_flow_logs(FlowLogIds=[flow_log["FlowLogId"]])
            logger.info(f"Successfully deleted flow log {flow_log['FlowLogId']} in {vpc['Region']}")
        else:
            logger.info(f"Dry-run enabled: did not delete flow log '{flow_log["FlowLogId"]}' of VPC '{vpc["VpcId"]}'")

        if "LogDestinationType" in flow_log:
            if flow_log["LogDestinationType"] == "cloud-watch-logs":
                cw_client = boto3.client("logs", region_name=vpc["Region"], **account_session)
                destination = flow_log["LogGroupName"]
                logger.debug(f"Deleting CloudWatch Log Group {destination}")
                if not dry_run:
                    cw_client.delete_log_group(logGroupName=destination)
                    logger.info(f"Successfully deleted CloudWatch Log Group {destination}")
                else:
                    logger.info(f"Dry-run enabled: did not delete Cloudwatch Log Group '{destination}'")

            elif flow_log["LogDestinationType"] == "s3":
                logger.warning(f"No action for S3 destination {destination}. Please handle manually.")


def main(dry_run: bool) -> None:
    """
    Main function to coordinate the cleanup.

    Args:
        dry_run (bool): Flag to enable/disable dry-run mode.
    """
    landing_zone_account_id = get_current_account_id()
    accounts = [acct for acct in get_all_accounts() if acct != landing_zone_account_id]
    logging.info(f"Begin scanning accounts for Control Tower VPC in {accounts}")

    for account_id in accounts:
        if account_id == landing_zone_account_id:
            logger.debug(f"Skipping Landing Zone account {account_id}")
            continue

        try:
            credentials = assume_role(account_id, ROLE_NAME)
            account_session = {
                "aws_access_key_id": credentials["AccessKeyId"],
                "aws_secret_access_key": credentials["SecretAccessKey"],
                "aws_session_token": credentials["SessionToken"]
            }
            vpcs = get_vpc_in_all_regions(account_session)
            for vpc in vpcs:
                logger.info(f"Processing VPC {vpc['VpcId']} in {vpc['Region']}")

                remove_nat_gateways(account_session, vpc, dry_run)
                remove_flow_logs(account_session, vpc, dry_run)
        except Exception as e:
            logger.error(f"Error processing account {account_id}: {e}")


def start(args=sys.argv):
    parser = argparse.ArgumentParser(description="AWS Control Tower Cleanup Script")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Enable dry-run mode (no changes will be made)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode (print debug log)")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info("Running in verbose mode.")
    else:
        logger.setLevel(logging.INFO)

    # mute boto3 logs
    for name in ['boto', 'urllib3', 's3transfer', 'boto3', 'botocore', 'nose']:
        logging.getLogger(name).setLevel(logging.CRITICAL)

    main(dry_run=args.dry_run)


if __name__ == "__main__":
    start()
