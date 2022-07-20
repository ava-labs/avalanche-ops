#!/usr/bin/env node
import 'source-map-support/register';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as cfn_inc from 'aws-cdk-lib/cloudformation-include';

export class AvalancheupStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: cdk.StackProps) {
    super(scope, id, props);
    console.log("CDK_ACCOUNT:", process.env.CDK_ACCOUNT);
    console.log("CDK_REGION:", process.env.CDK_REGION);

    const tmpl = new cfn_inc.CfnInclude(this, `included-template-avalancheup-${process.env.AVALANCHEUP_ID || ''}`, {
      templateFile: path.join('cfn-templates', 'avalancheup.yaml'),
      parameters: {
        'ClusterId': process.env.AVALANCHEUP_ID,
        'KmsCmkArn': process.env.AVALANCHEUP_KMS_CMK_ARN,
        'S3BucketName': process.env.AVALANCHEUP_S3_BUCKET_NAME,
        'NetworkId': process.env.AVALANCHEUP_NETWORK_ID,
        'AadTag': process.env.AVALANCHEUP_AAD_TAG,
        'Ec2KeyPairName': process.env.AVALANCHEUP_EC2_KEY_PAIR_NAME,
      },
    });
    const clusterId = new cdk.CfnParameter(this, 'ClusterId', {
      type: 'String',
      description: 'ClusterId',
      default: process.env.AVALANCHEUP_ID,
    });
    console.log('id 👉', clusterId.valueAsString);

    const kmsCmkArn = new cdk.CfnParameter(this, 'KmsCmkArn', {
      type: 'String',
      description: 'KmsCmkArn',
      default: process.env.AVALANCHEUP_KMS_CMK_ARN,
    });
    console.log('kmsCmkArn 👉', kmsCmkArn.valueAsString);

    const s3BucketName = new cdk.CfnParameter(this, 'S3BucketName', {
      type: 'String',
      description: 'S3BucketName',
      default: process.env.AVALANCHEUP_S3_BUCKET_NAME,
    });
    console.log('s3BucketName 👉', s3BucketName.valueAsString);

    const networkId = new cdk.CfnParameter(this, 'NetworkId', {
      type: 'Number',
      description: 'NetworkId',
      default: process.env.AVALANCHEUP_NETWORK_ID,
    });
    console.log('networkId 👉', networkId.valueAsNumber);

    const aadTag = new cdk.CfnParameter(this, 'AadTag', {
      type: 'String',
      description: 'AadTag',
      default: process.env.AVALANCHEUP_AAD_TAG,
    });
    console.log('aadTag 👉', aadTag.valueAsString);

    const ec2KeyPairName = new cdk.CfnParameter(this, 'Ec2KeyPairName', {
      type: 'String',
      description: 'Ec2KeyPairName',
      default: process.env.AVALANCHEUP_EC2_KEY_PAIR_NAME,
    });
    console.log('ec2KeyPairName 👉', ec2KeyPairName.valueAsString);

    new cdk.CfnOutput(this, "instanceProfileArn", {
      value: tmpl.getOutput('InstanceProfileArn').logicalId,
      exportName: "instanceProfileArn",
    });
    new cdk.CfnOutput(this, "instanceRoleArn", {
      value: tmpl.getOutput('InstanceRoleArn').logicalId,
      exportName: "instanceRoleArn",
    });
    new cdk.CfnOutput(this, "nlbDnsName", {
      value: tmpl.getOutput('NlbDnsName').logicalId,
      exportName: "nlbDnsName",
    });
  }
}

const app = new cdk.App();

new AvalancheupStack(app, 'avalancheup-stack', {
  stackName: 'avalancheup-stack',
  env: {
    account: process.env.CDK_ACCOUNT || process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_REGION || process.env.CDK_DEFAULT_REGION
  },
});

app.synth();
