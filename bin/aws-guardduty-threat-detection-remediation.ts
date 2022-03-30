#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { GuarddutyEnableStack } from '../lib/guardduty';
import { GuarddutyHandsOnStack } from '../lib/hands-on';

const env  = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION
};

const app = new cdk.App();
new GuarddutyEnableStack(app, 'GuarddutyEnableStack', { env });
new GuarddutyHandsOnStack(app, 'GuarddutyHandsOnStack', { env });
