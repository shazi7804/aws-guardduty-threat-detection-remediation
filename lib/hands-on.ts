import { Stack, StackProps, Tags, Duration } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { VpcProvider } from './vpc';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as ddb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';

const config = require('../config.json');

export class GuarddutyHandsOnStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const namePrefix = config.namePrefix;
    const email = config.email;

    const vpc = VpcProvider.createSimple(this);

    const ddbPassword = new ssm.StringParameter(this, 'dynamodb-password', {
      description: 'Sample secret for generating GuardDuty findings.',
      parameterName: 'guardduty_dynamodb_password_sample',
      stringValue: 'NA',
    });

    const custDDB = new ddb.Table(this, 'Table', {
      tableName: namePrefix + '-CustomerDB',
      partitionKey: { name: 'name', type: ddb.AttributeType.STRING },
      readCapacity: 5,
      writeCapacity: 5
    });

    const guarddutyThreatListBucket = new s3.Bucket(this, 'guardduty-threat-list-bucket', {
      bucketName: 'guardduty-threat-list-' + this.region + '-' + this.account
    });

    const guarddutyLogBucket = new s3.Bucket(this, 'guardduty-log-bucket', {
      bucketName: 'guardduty-log-' + this.region + '-' + this.account,
      accessControl: s3.BucketAccessControl.LOG_DELIVERY_WRITE
    });

    const guarddutyCompromisedBucket = new s3.Bucket(this, 'guardduty-compromised-bucket', {
      bucketName: 'guardduty-compromised-' + this.region + '-' + this.account,
      serverAccessLogsBucket: guarddutyLogBucket
    });

    const machineImage = new ec2.AmazonLinuxImage({
      generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
      edition: ec2.AmazonLinuxEdition.STANDARD,
      virtualization: ec2.AmazonLinuxVirt.HVM,
      storage: ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
      cpuType: ec2.AmazonLinuxCpuType.X86_64
    });

    const role = new iam.Role(this, 'role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonEC2RoleforSSM')
      ]
    });

    const securityGroup = new ec2.SecurityGroup(this, "security-group", {
      vpc,
      allowAllOutbound: true,
      securityGroupName: namePrefix + "-target",
    });
    securityGroup.addIngressRule(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.allIcmp(), "Allow ICMP traffic from a specific IP range");

    // Malicious Instance: Scenario 1 & 2 - For GuardDuty Finding: UnauthorizedAccess:EC2/MaliciousIPCaller.Custom
    const maliciousUser1Policy = new iam.Policy(this, 'malicious-iam-user-1-policy', {
      statements: [
        new iam.PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:DescribeParameters'],
          resources: ["arn:aws:ssm:" + this.region + ":" + this.account + ":*"],
        }),
      ],
    });

    const maliciousUser1 = new iam.User(this, 'malicious-iam-user-1');
    maliciousUser1.attachInlinePolicy(maliciousUser1Policy);

    const maliciousUser1AccessKey = new iam.AccessKey(this, 'malicious-iam-user-1-access-key', {
      user: maliciousUser1,
      serial: 1
    });
    
    const maliciousUserData1 = ec2.UserData.forLinux();
    maliciousUserData1.addCommands(...[
        'mkdir /home/ec2-user/.aws',
        'touch /home/ec2-user/.aws/credentials /home/ec2-user/.aws/config',
        'cat <<EOT >> /home/ec2-user/.aws/credentials',
        '[default]',
        "aws_access_key_id = " + maliciousUser1AccessKey.accessKeyId,
        "aws_secret_access_key = " + maliciousUser1AccessKey.secretAccessKey,
        'EOT',
        'chmod 746 /home/ec2-user/.aws/credentials',
        'chown ec2-user /home/ec2-user/.aws/credentials',
        'chmod 746 /home/ec2-user/.aws/config',
        'chown ec2-user /home/ec2-user/.aws/config',
        'cat <<EOT >> /home/ec2-user/gd-findings.sh',
        '#!/bin/bash',
        'aws configure set default.region ' + this.region,
        'aws iam get-user',
        'aws iam create-user --user-name ' + namePrefix + '-Sarah',
        'aws dynamodb list-tables',
        'aws s3api list-buckets',
        'aws ssm describe-parameters',
        'aws ssm get-parameters --names ' + ddbPassword.parameterName,
        'sleep 10m',
        'aws s3api list-objects --bucket ' + guarddutyCompromisedBucket.bucketName,
        'EOT',
        'chmod 744 /home/ec2-user/gd-findings.sh',
        'chown ec2-user /home/ec2-user/gd-findings.sh',
        'echo "* * * * * /home/ec2-user/gd-findings.sh > /home/ec2-user/gd-findings.log 2>&1" | tee -a /var/spool/cron/ec2-user'
    ]);
    maliciousUserData1.render();

    const maliciousInstance1 = new ec2.Instance(this, 'malicious-instance-1', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage,
      securityGroup,
      userData: maliciousUserData1,
      vpcSubnets: vpc.selectSubnets({
          subnets: vpc.publicSubnets
      }),
      role
    });
    Tags.of(maliciousInstance1).add("Name", namePrefix + '-MaliciousInstance-Scenario-1-2');
    
    const maliciousIP = new ec2.CfnEIP(this, 'malicious-ip', {
      domain: 'vpc',
      instanceId: maliciousInstance1.instanceId,
    });
    
    // Malicious Instance: Scenario 4 - For GuardDuty S3 Findings, Stealth and Policy
    const maliciousUser2Policy = new iam.Policy(this, 'malicious-iam-user-2-policy', {
      statements: [
        new iam.PolicyStatement({
          actions: ['s3:PutBucketPublicAccessBlock', 's3:PutBucketLogging'],
          resources: ["arn:aws:s3::*"],
        }),
      ],
    });

    const maliciousUser2 = new iam.User(this, 'malicious-iam-user-2');
    maliciousUser2.attachInlinePolicy(maliciousUser2Policy);

    const maliciousUser2AccessKey = new iam.AccessKey(this, 'malicious-iam-user-2-access-key', {
      user: maliciousUser2,
      serial: 1
    });

    const maliciousUserData2 = ec2.UserData.forLinux();
    maliciousUserData2.addCommands(...[
        'mkdir /home/ec2-user/.aws',
        'touch /home/ec2-user/.aws/credentials /home/ec2-user/.aws/config',
        'cat <<EOT >> /home/ec2-user/.aws/credentials',
        '[default]',
        "aws_access_key_id = " + maliciousUser2AccessKey.accessKeyId,
        "aws_secret_access_key = " + maliciousUser2AccessKey.secretAccessKey,
        'EOT',
        'chmod 746 /home/ec2-user/.aws/credentials',
        'chown ec2-user /home/ec2-user/.aws/credentials',
        'chmod 746 /home/ec2-user/.aws/config',
        'chown ec2-user /home/ec2-user/.aws/config',
        'sleep 20m',
        'cat <<EOT >> /home/ec2-user/gd-findings.sh',
        '#!/bin/bash',
        'aws configure set default.region ' + this.region,
        'aws s3api list-buckets',
        'aws s3api delete-public-access-block --bucket ' + guarddutyCompromisedBucket.bucketName,
        'aws s3api put-bucket-logging --bucket ' + guarddutyCompromisedBucket.bucketName + ' --bucket-logging-status {}',
        'EOT',
        'chmod 744 /home/ec2-user/gd-findings.sh',
        'chown ec2-user /home/ec2-user/gd-findings.sh',
        'echo "* * * * * /home/ec2-user/gd-findings.sh > /home/ec2-user/gd-findings.log 2>&1" | tee -a /var/spool/cron/ec2-user'
    ]);
    maliciousUserData2.render();

    const maliciousInstance2 = new ec2.Instance(this, 'malicious-instance-2', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage,
      securityGroup,
      userData: maliciousUserData2,
      vpcSubnets: vpc.selectSubnets({
          subnets: vpc.publicSubnets
      }),
      role
    });
    Tags.of(maliciousInstance2).add("Name", namePrefix + '-MaliciousInstance-Scenario-4');

    // Compromised Instance: Scenario 1 - For GuardDuty Finding: UnauthorizedAccess:EC2/MaliciousIPCaller.Custom
    const compromisedUserData1 = ec2.UserData.forLinux();
    compromisedUserData1.addCommands(...[
      'exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1',
      'sleep 5m',
      'echo BEGIN',
      'echo "* * * * * ping -c 6 -i 10 '+maliciousIP.ref+' | tee -a /var/spool/cron/ec2-user'
    ]);
    maliciousUserData2.render();

    const compromisedInstance1 = new ec2.Instance(this, 'compromised-instance-1', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage,
      securityGroup,
      userData: compromisedUserData1,
      vpcSubnets: vpc.selectSubnets({
          subnets: vpc.publicSubnets
      }),
      role
    });
    Tags.of(compromisedInstance1).add("Name", namePrefix + '-CompromisedInstance-Scenario-1');

    // Compromised Instance: Scenario 3 - IAM Role - For GuardDuty Finding: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
    const compromisedRole = new iam.Role(this, 'compromised-role', {
      assumedBy: new iam.ServicePrincipal('ec2'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonEC2RoleforSSM')],
      inlinePolicies: {
        GuardDutyCompromisedPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                "ssm:PutParameter",
                "ssm:DescribeParameters",
                "ssm:GetParameters",
                "ssm:DeleteParameter",
                "ssm:DescribeParameters",
                "dynamodb:*",
                "guardduty:*",
                "s3:PutObject",
                "s3:PutAccountPublicAccessBlock",
                "iam:PutRolePolicy"
              ],
              resources: ["*"]
            })
          ]
        })
      }
    })

    const compromisedUserData2 = ec2.UserData.forLinux();
    compromisedUserData2.addCommands(...[
      'aws configure set default.region ' + this.region,
      'uuid=$(uuidgen)',
      'list="gd-threat-list-example-$uuid.txt"',
      'maliciousip=`curl http://169.254.169.254/latest/meta-data/public-ipv4`',
      'echo '+maliciousIP.ref+' >> $list',
      'aws s3 cp $list s3://' + guarddutyThreatListBucket.bucketName + '/$list',
      'sleep 5',

      'aws s3control put-public-access-block --account-id ' + this.account + ' --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
      'id=`aws guardduty list-detectors --query \'DetectorIds[0]\' --output text`',

      'n=0',
      'until [ "$n" -ge 5 ]',
      'do',
      '  aws guardduty create-threat-intel-set --activate --detector-id $id --format TXT --location https://s3.amazonaws.com/'  + guarddutyThreatListBucket.bucketName + '/$list --name Example-Threat-List && break',
      '  n=$((n+1))',
      '  sleep 5',
      'done',
      
      // Set Parameters in SSM
      'aws ssm put-parameter --name ' + ddbPassword.parameterName + ' --type "SecureString" --value Password123 --overwrite',

      // Add Item to Customer DB
      'aws dynamodb put-item --table-name '+ custDDB.tableName + ' --item \'{ "name": { "S": "Joshua Tree" }, "state": {"S": "California"}, "website":{"S": "https://www.nps.gov/jotr/index.htm"} }\''
    ]);
    maliciousUserData2.render();

    const compromisedInstance2 = new ec2.Instance(this, 'compromised-instance-2', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage,
      securityGroup,
      userData: compromisedUserData2,
      vpcSubnets: vpc.selectSubnets({
          subnets: vpc.publicSubnets
      }),
      role: compromisedRole
    });
    Tags.of(compromisedInstance2).add("Name", namePrefix + '-CompromisedInstance-Scenario-3');

    // GuardDuty Findings SNS Topic
    const topic = new sns.Topic(this, 'sns-topic');
    topic.addSubscription(new subscriptions.EmailSubscription(email))
    const topicPolicy = new sns.TopicPolicy(this, 'sns-topic-policy', {
      topics: [topic],
    });
    topicPolicy.document.addStatements(new iam.PolicyStatement({
      actions: ["sns:Publish"],
      principals: [new iam.ServicePrincipal('events')],
      resources: [topic.topicArn],
    }));

    // Remediation Lambda - Instance Credential Exfiltration (ICE)
    const remediationLambdaRole = new iam.Role(this, 'remediation-lambda-role', {
      assumedBy: new iam.ServicePrincipal('lambda'),
      inlinePolicies: {
        InstanceCredentialExfiltration: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                "ssm:DescribeParameters",
                "ssm:GetParameter",
                "ssm:GetParameters",
                "ec2:ReplaceIamInstanceProfileAssociation",
                "ec2:DescribeIamInstanceProfileAssociations",
                "iam:CreateInstanceProfile",
                "iam:AddRoleToInstanceProfile",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:ListInstanceProfilesForRole",
                "iam:DeleteInstanceProfile",
                "iam:PassRole",
                "iam:PutRolePolicy",
                "sns:Publish",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
              ],
              resources: ["*"]
            })
          ]
        })
      }
    });

    const remediationLambda = new lambda.Function(this, "remediation-lambda", {
      code: new lambda.AssetCode("./lambda/remediation"),
      handler: "index.handler",
      runtime: lambda.Runtime.PYTHON_3_8,
      timeout: Duration.seconds(35),
      environment: {
        TOPIC_ARN: topic.topicArn
      },
      role: remediationLambdaRole
    });

    // GuardDuty CloudWatch Event - For GuardDuty Finding: UnauthorizedAccess:EC2/MaliciousIPCaller.Custom
    const guarddutyEc2EventRule = new events.Rule(this, 'guardduty-ec2-event-rule', {
      ruleName: namePrefix + '-EC2-MaliciousIPCaller',
      eventPattern: {
        source: ["aws.guardduty"],
        detail: {
          type: ['UnauthorizedAccess:EC2/MaliciousIPCaller.Custom']
        },
      },
    });
    guarddutyEc2EventRule.addTarget(new targets.LambdaFunction(remediationLambda));
    guarddutyEc2EventRule.addTarget(new targets.SnsTopic(topic, {
      message: events.RuleTargetInput.fromText('GuardDuty Finding | ID:'+events.EventField.fromPath("$.detail.id")+': The EC2 instance '+events.EventField.fromPath("$.detail.resource.instanceDetails.instanceId")+' may be compromised and should be investigated. Go to https://console.aws.amazon.com/guardduty/home?region='+events.EventField.fromPath("$.detail.region")+'#/findings?macros=current&fId='+events.EventField.fromPath("$.detail.id")),
    }));
  

    // GuardDuty CloudWatch Event - For GuardDuty Finding: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
    const guarddutyIamInstanceCredentialEventRule = new events.Rule(this, 'guardduty-event-iam-instance-credential-exfiltration-rule', {
      ruleName: namePrefix + '-IAMUser-InstanceCredentialExfiltration',
      eventPattern: {
        source: ["aws.guardduty"],
        detail: {
          type: ['UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS']
        }
      },
    });
    guarddutyIamInstanceCredentialEventRule.addTarget(new targets.LambdaFunction(remediationLambda));
    guarddutyIamInstanceCredentialEventRule.addTarget(new targets.SnsTopic(topic, {
      message: events.RuleTargetInput.fromText('GuardDuty Finding | ID:'+events.EventField.fromPath("$.detail.id")+': An EC2 instance IAM credentials (Role: '+events.EventField.fromPath("$.detail.resource.accessKeyDetails.userName")+') may be compromised and should be investigated. Go to https://console.aws.amazon.com/guardduty/home?region='+events.EventField.fromPath("$.detail.region")+'#/findings?macros=current&fId='+events.EventField.fromPath("$.detail.id")),
    }))

    // GuardDuty CloudWatch Event - For GuardDuty Finding: UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom
    const guarddutyIamUserEventRule = new events.Rule(this, 'guardduty-iam-user-event-rule', {
      ruleName: namePrefix + '-IAMUser-MaliciousIPCaller',
      eventPattern: {
        source: ["aws.guardduty"],
        detail: {
          type: [
            'UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom',
            'Discovery:S3/MaliciousIPCaller.Custom'
          ]
        }
      },
    });
    guarddutyIamUserEventRule.addTarget(new targets.SnsTopic(topic, {
      message: events.RuleTargetInput.fromText('GuardDuty Finding | ID:'+events.EventField.fromPath("$.detail.id")+': An AWS API operation was invoked (userName: '+events.EventField.fromPath("$.detail.resource.accessKeyDetails.userName")+') from an IP address that is included on your threat list and should be investigated. Go to https://console.aws.amazon.com/guardduty/home?region='+events.EventField.fromPath("$.detail.region")+'#/findings?macros=current&fId='+events.EventField.fromPath("$.detail.id")),
    }))
    
    // GuardDuty CloudWatch Event - For GuardDuty S3 findings Stealth:S3/ServerAccessLoggingDisabled & Policy:S3/BucketBlockPublicAccessDisabled
    const guarddutyBucketStealthEventRule = new events.Rule(this, 'guardduty-bucket-stealth-event-rule', {
      ruleName: namePrefix + '-S3-Stealth-Policy',
      eventPattern: {
        source: ["aws.guardduty"],
        detail: {
          type: [
            'Policy:S3/BucketBlockPublicAccessDisabled',
            'Stealth:S3/ServerAccessLoggingDisabled'
          ]
        }
      },
    });
    guarddutyBucketStealthEventRule.addTarget(new targets.SnsTopic(topic, {
      message: events.RuleTargetInput.fromText('GuardDuty Finding | ID:'+events.EventField.fromPath("$.detail.id")+': An AWS S3 related API operation was invoked by user (userName: '+events.EventField.fromPath("$.detail.resource.accessKeyDetails.userName")+') in account '+events.EventField.fromPath("$.detail.accountId")+' . This activity seems suspicious. Please investigate with the user to check if this was expectated behaviour. Go to https://console.aws.amazon.com/guardduty/home?region='+events.EventField.fromPath("$.detail.region")+'#/findings?macros=current&fId='+events.EventField.fromPath("$.detail.id")),
    }))



  }
}
