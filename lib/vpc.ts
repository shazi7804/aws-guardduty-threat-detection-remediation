import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

export class VpcProvider extends cdk.Stack {
    public static createSimple(scope: Construct) {
        const stack = cdk.Stack.of(scope)

        const vpc = stack.node.tryGetContext('use_default_vpc') === '1' ?
            ec2.Vpc.fromLookup(stack, 'Vpc', { isDefault: true }) :
            stack.node.tryGetContext('use_vpc_id') ?
                ec2.Vpc.fromLookup(stack, 'Vpc', { vpcId: stack.node.tryGetContext('use_vpc_id') }) :
                new ec2.Vpc(stack, 'Vpc', { maxAzs: 3, natGateways: 1 });

    return vpc
    }
}