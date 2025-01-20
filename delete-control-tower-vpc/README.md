# Delete Control Tower VPC

This Python script automates the deletion of VPCs and associated resources created by AWS Control Tower. It removes:
1. **NAT Gateways** in the identified VPCs.
2. **VPC Flow Logs** and their destinations (CloudWatch Log Groups or S3).

[Related Incident Report](https://docs.google.com/document/d/1ZunI43UP89DUdgK5cBsRmQEHRWfMlAK80KZoLOdOg3o/edit?usp=sharing)

## Features

- **Cross-Account Access:** Uses the `AWSControlTowerExecution` role to access each AWS account in your organization.
- **Dry-Run Mode:** Preview actions without making any changes.
- **Detailed Logging:** Provides logs for actions and potential issues.

## Prerequisites

- **Python 3.12+** installed.
- **Poetry** for dependency management. Install Poetry using:
  ```bash
  pip install poetry
  ```

## Running this script
```bash
# dry-run
❯ poetry run delete-vpc --dry-run

# view usage
❯ poetry run delete-vpc -h
usage: delete-vpc [-h] [-d] [-v]

AWS Control Tower Cleanup Script

options:
  -h, --help     show this help message and exit
  -d, --dry-run  Enable dry-run mode (no changes will be made)
  -v, --verbose  Enable verbose mode (print debug log)
```