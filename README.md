# Amazon GuardDuty Threat Detection and Remediation

This repository walks you through a scenario covering threat detection and remediation using Amazon GuardDuty;

## Table of contents

- [Architecture](#architecture)
- [Scenarios](#scenarios)
- [Deployment](#deployment-steps)
- [Test](#test)

## Architecture
###  Architecture Diagram

TBD ...

- `GuarddutyEnabledStack`: This stack for enabled detector setting.
- `GuarddutyHandsOnStack`: This stack will deploy malicious and compromised instances and resources.

###  Components Details
- [**AWS CDK**](https://aws.amazon.com/cdk/) – This solution uses the CDK Template language in Typescript to create each resource.
- [**Amazon EC2**](https://aws.amazon.com/ec2/) – It's will created 2 malicious instances and 2 compromised instance.
- [**Amazon S3**](https://aws.amazon.com/s3/) – Logging and compromised detection data is stored in an Simple Storage Service (S3) Bucket.
- [**Amazon DynamoDB**](https://aws.amazon.com/dynamodb/) – Sample for compromised database table.
- [**Amazon SNS**](https://aws.amazon.com/sns/) – Notification.
- [**AWS Lambda**](https://aws.amazon.com/sns/) – Capture GuardDuty finding event and send response email to Admin.
- [**Amazon Eventbridge**](https://aws.amazon.com/sns/) – Capture GuardDuty finding event and send response email to Admin.

## Scenarios

| Scenario | GuardDuty Finding |
|-----------|:-------------:|
| [Compromised AWS IAM credentials](https://catalog.workshops.aws/guardduty/en-US/module7) | UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom |
| [Compromised EC2 instance](https://catalog.workshops.aws/guardduty/en-US/module8) | UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom |
| [Compromised S3 Bucket](https://catalog.workshops.aws/guardduty/en-US/module9) | Stealth:S3/ServerAccessLoggingDisabled |
| IAM Role credential exfiltration | (TBD)UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS |
| EKS Findings Remediation | (TBD)Policy:Kubernetes/AdminAccessToDefaultServiceAccount |
| EKS Findings Remediation | (TBD)Discovery:Kubernetes/SuccessfulAnonymousAccess |
| EKS Findings Remediation | (TBD)Policy:Kubernetes/AnonymousAccessGranted |
| EKS Findings Remediation | (TBD)Execution:Kubernetes/ExecInKubeSystemPod |
| EKS Findings Remediation | (TBD)PrivilegeEscalation:Kubernetes/PrivilegedContainer |
| EKS Findings Remediation | (TBD)Persistence:Kubernetes/ContainerWithSensitiveMount |
| EKS Findings Remediation | (TBD)Policy:Kubernetes/ExposedDashboard |

## Deployment Steps
###  Step 1. Prepare an AWS Account and IAM Access
Create your AWS account at [http://aws.amazon.com](http://aws.amazon.com) by following the instructions on the site. Then create IAM User permission setting `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in your environment variables.

###  Step 2. CDK Install and Bootstarp

Install [AWS CDK CLI](https://docs.aws.amazon.com/cdk/latest/guide/tools.html) from npm

```bash
$ npm i -g aws-cdk
```

For first initial, run `bootstrap` deploy in your acoount.

```bash
$ cdk bootstrap aws://${your-account-id}/us-east-1
```

Install dependencies packages.

```bash
$ npm install
```

### Step 3. Configuration 

Configuration setting file [config.json](./cdk.context.json), The deployment administrator will be notified for revoke old sessions.

```
# config.json
{
    "namePrefix": "GuardDuty-HandsOn",
    "email": "root@mail.com"
}
```

###  Step 4. Deploy

```bash
$ cdk ls
GuarddutyEnabledStack
GuarddutyHandsOnStack
```

If you have enabled the GuardDuty dectector setting, then you can deploy `GuarddutyHandsOnStack` directly
```bash
$ cdk deploy GuarddutyHandsOnStack
```

Or deploy all stacks

```bash
$ cdk deploy --all
```

## Test

To build the project and run the test, issue these commands.

```
$ npm run build && npm test
```