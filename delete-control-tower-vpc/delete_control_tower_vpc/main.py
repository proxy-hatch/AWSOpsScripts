from os import removedirs

import boto3
import logging
import sys
import argparse
from typing import Dict, List, Any
from botocore.exceptions import ClientError

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


def get_control_tower_vpc_in_all_regions(account_session: Dict[str, str]) -> List[Dict[str, str]]:
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


def remove_vpc_dependencies(account_session: Dict[str, str], vpc: Dict[str, str], dry_run: bool) -> None:
    """
    Delete all dependencies of the specified VPC, including NAT Gateways, Flow Logs, Subnets,
    Security Groups, Network ACLs, Internet Gateways, Route Tables, and VPC Endpoints.

    Args:
        account_session (Dict[str, str]): AWS session credentials for the target account.
        vpc (Dict[str, str]): VPC information with region and VPC ID.
        dry_run (bool): Flag to enable/disable dry-run mode.
    """
    regional_ec2 = boto3.client("ec2", region_name=vpc["Region"], **account_session)
    vpc_id = vpc['VpcId']

    # Delete NAT Gateways
    try:
        response = regional_ec2.describe_nat_gateways(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for nat_gw in response.get("NatGateways", []):
            logger.debug(f"Deleting NAT Gateway {nat_gw['NatGatewayId']} in {vpc['Region']}")
            if not dry_run:
                regional_ec2.delete_nat_gateway(NatGatewayId=nat_gw["NatGatewayId"])
                logger.info(f"Deleted NAT Gateway {nat_gw['NatGatewayId']} in {vpc['Region']}")
            else:
                logger.info(f"Dry-run: Skipping deletion of NAT Gateway {nat_gw['NatGatewayId']}")
    except ClientError as e:
        logger.error(f"Error deleting NAT Gateways for VPC {vpc_id}: {e}")

    # Delete VPC Endpoints
    try:
        response = regional_ec2.describe_vpc_endpoints(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for vpce in response.get("VpcEndpoints", []):
            logger.debug(f"Deleting VPC Endpoint {vpce['VpcEndpointId']}")
            if not dry_run:
                regional_ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce["VpcEndpointId"]])
                logger.info(f"Deleted VPC Endpoint {vpce['VpcEndpointId']}")
            else:
                logger.info(f"Dry-run: Skipping deletion of VPC Endpoint {vpce['VpcEndpointId']}")
    except Exception as e:
        logger.error(f"Error deleting VPC Endpoints for VPC {vpc_id}: {e}")

    # Delete Flow Logs
    try:
        response = regional_ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])
        for flow_log in response.get("FlowLogs", []):
            logger.debug(f"Deleting Flow Log {flow_log['FlowLogId']} in {vpc['Region']}")
            if not dry_run:
                regional_ec2.delete_flow_logs(FlowLogIds=[flow_log["FlowLogId"]])
                logger.info(f"Deleted Flow Log {flow_log['FlowLogId']} in {vpc['Region']}")
            else:
                logger.info(f"Dry-run: Skipping deletion of Flow Log {flow_log['FlowLogId']}")

            # Delete destinations (CloudWatch Logs or S3)
            if flow_log["LogDestinationType"] == "cloud-watch-logs":
                cw_client = boto3.client("logs", region_name=vpc["Region"], **account_session)
                destination = flow_log["LogGroupName"]
                logger.debug(f"Deleting CloudWatch Log Group {destination}")
                if not dry_run:
                    cw_client.delete_log_group(logGroupName=destination)
                    logger.info(f"Deleted CloudWatch Log Group {destination}")
                else:
                    logger.info(f"Dry-run: Skipping deletion of CloudWatch Log Group {destination}")
            elif flow_log["LogDestinationType"] == "s3":
                logger.warning(f"Flow Log destination is S3: Manual cleanup required for {flow_log['LogDestination']}")
    except ClientError as e:
        logger.error(f"Error deleting Flow Logs for VPC {vpc_id}: {e}")

    # Delete Network ACLs
    try:
        response = regional_ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for n_acl in response.get("NetworkAcls", []):
            if not n_acl["IsDefault"]:  # Skip default NACL
                logger.debug(f"Deleting Network ACL {n_acl['NetworkAclId']} in {vpc['Region']}")
                if not dry_run:
                    regional_ec2.delete_network_acl(NetworkAclId=n_acl["NetworkAclId"])
                    logger.info(f"Deleted Network ACL {n_acl['NetworkAclId']}")
                else:
                    logger.info(f"Dry-run: Skipping deletion of Network ACL {n_acl['NetworkAclId']}")
    except Exception as e:
        logger.error(f"Error deleting Network ACLs for VPC {vpc_id}: {e}")

    # Detach and Delete Internet Gateway
    try:
        response = regional_ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])
        for igw in response.get("InternetGateways", []):
            logger.debug(f"Detaching Internet Gateway {igw['InternetGatewayId']} from VPC {vpc_id}")
            if not dry_run:
                regional_ec2.detach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id)
                regional_ec2.delete_internet_gateway(InternetGatewayId=igw["InternetGatewayId"])
                logger.info(f"Detached and deleted Internet Gateway {igw['InternetGatewayId']} for VPC {vpc_id}")
            else:
                logger.info(f"Dry-run: Skipping detachment and deletion of Internet Gateway {igw['InternetGatewayId']}")
    except Exception as e:
        logger.error(f"Error detaching and deleting Internet Gateway for VPC {vpc_id}: {e}")

    # Delete Route Tables
    try:
        response = regional_ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for rt in response.get("RouteTables", []):
            if not rt.get("Associations"):  # Skip main route table
                logger.debug(f"Deleting Route Table {rt['RouteTableId']}")
                if not dry_run:
                    regional_ec2.delete_route_table(RouteTableId=rt["RouteTableId"])
                    logger.info(f"Deleted Route Table {rt['RouteTableId']}")
                else:
                    logger.info(f"Dry-run: Skipping deletion of Route Table {rt['RouteTableId']}")
    except Exception as e:
        logger.error(f"Error deleting Route Tables for VPC {vpc_id}: {e}")

    # Delete Subnets
    try:
        response = regional_ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for subnet in response.get("Subnets", []):
            logger.debug(f"Deleting Subnet {subnet['SubnetId']} in {vpc['Region']}")
            if not dry_run:
                regional_ec2.delete_subnet(SubnetId=subnet["SubnetId"])
                logger.info(f"Deleted Subnet {subnet['SubnetId']} in {vpc['Region']}")
            else:
                logger.info(f"Dry-run: Skipping deletion of Subnet {subnet['SubnetId']}")
    except ClientError as e:
        logger.error(f"Error deleting Subnets for VPC {vpc_id}: {e}")

    # Delete Security Groups
    try:
        response = regional_ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for sg in response.get("SecurityGroups", []):
            if sg["GroupName"] != "default":  # Skip default security group
                logger.debug(f"Deleting Security Group {sg['GroupId']} in {vpc['Region']}")
                if not dry_run:
                    regional_ec2.delete_security_group(GroupId=sg["GroupId"])
                    logger.info(f"Deleted Security Group {sg['GroupId']} in {vpc['Region']}")
                else:
                    logger.info(f"Dry-run: Skipping deletion of Security Group {sg['GroupId']}")
    except ClientError as e:
        logger.error(f"Error deleting Security Groups for VPC {vpc_id}: {e}")


def remove_vpc(account_session: Dict[str, str], vpc: Dict[str, str], dry_run: bool):
    regional_ec2 = boto3.client("ec2", region_name=vpc["Region"], **account_session)
    vpc_id = vpc["VpcId"]

    try:
        logger.debug(f"Deleting VPC: {vpc_id}")
        if not dry_run:
            regional_ec2.delete_vpc(VpcId=vpc_id)
            logger.info(f"Successfully deleted VPC: {vpc_id}")
        else:
            logger.info(f"Dry-run enabled: did not delete VPC: {vpc_id}")

    except ClientError as e:
        logger.error(f"Failed to delete VPC {vpc_id}: {e}")


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
            vpcs = get_control_tower_vpc_in_all_regions(account_session)
            for vpc in vpcs:
                logger.info(f"Processing VPC {vpc['VpcId']} in {account_id} {vpc['Region']}")
                remove_vpc_dependencies(account_session, vpc, dry_run)
                remove_vpc(account_session, vpc, dry_run)
        except Exception as e:
            logging.exception(f"Error processing account {account_id}:")


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
