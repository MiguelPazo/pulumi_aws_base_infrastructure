/**
 * Created by Miguel Pazo (https://miguelpazo.com)
 */
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";
import * as random from "@pulumi/random";
import * as pulumi from "@pulumi/pulumi";
import * as config from "./config";
import * as fs from 'fs';


/**
 *  Creating VPC
 */
const vpc = new awsx.ec2.Vpc(`${config.generalTagName}-vpc`, {
    numberOfAvailabilityZones: 2,
    numberOfNatGateways: config.numberOfNatGateways,
    tags: {
        Name: `${config.generalTagName}-vpc`,
        [config.generalTagName]: "shared",
    }
});

if (['production'].indexOf(config.stack) !== -1) {
    const logGroup = new aws.cloudwatch.LogGroup(`${config.generalTagName}-logGroup`, {});

    const logRole = new aws.iam.Role(`${config.generalTagName}-logGroup-role`, {
        assumeRolePolicy: {
            Version: "2012-10-17",
            Statement: [
                {
                    Sid: "",
                    Effect: "Allow",
                    Principal: {
                        Service: "vpc-flow-logs.amazonaws.com"
                    },
                    Action: "sts:AssumeRole"
                }
            ]
        },
    });

    new aws.ec2.FlowLog(`${config.generalTagName}-logGroup-flowLog`, {
        iamRoleArn: logRole.arn,
        logDestination: logGroup.arn,
        trafficType: "ALL",
        vpcId: vpc.id,
    });

    new aws.iam.RolePolicy(`${config.generalTagName}-logGroup-rolePolicy`, {
        policy: {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ]
        },
        role: logRole.id,
    });
}


/**
 * Creating ALB
 */
let logsBucket;
let enableDeletionProtection = false;
let accessLogs = {
    bucket: '',
    enabled: false
};

if (['production'].indexOf(config.stack) !== -1) {
    enableDeletionProtection = true;

    logsBucket = new aws.s3.Bucket(`${config.generalTagName}-alb-logs`, {
        bucket: `${config.generalTagName}2-alb-logs`,
        acl: "private",
        tags: {
            Name: `${config.generalTagName}-alb-logs`,
            [config.generalTagName]: "shared",
        }
    });

    new aws.s3.BucketPolicy(`${config.generalTagName}-alb-logs-bucket-policy`, {
        bucket: logsBucket.id,
        policy: pulumi.all([logsBucket.arn])
            .apply(([bucketArn]) => JSON.stringify({
                Version: "2012-10-17",
                Id: `${config.generalTagName}-alb-logs-bucket-policy`,
                Statement: [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::127311923021:root"
                        },
                        "Action": "s3:PutObject",
                        "Resource": `${bucketArn}/*`
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "delivery.logs.amazonaws.com"
                        },
                        "Action": "s3:PutObject",
                        "Resource": `${bucketArn}/*`,
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "delivery.logs.amazonaws.com"
                        },
                        "Action": "s3:GetBucketAcl",
                        "Resource": bucketArn
                    }
                ],
            })),
    });

    accessLogs = {
        bucket: logsBucket.bucket,
        enabled: true
    }
}

const securityGroupAlb = new awsx.ec2.SecurityGroup(`${config.generalTagName}-alb-sg`, {
    vpc,
    egress: [
        {protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"]}
    ],
    tags: {
        Name: `${config.generalTagName}-alb-sg`,
        [config.generalTagName]: "shared",
    }
});

const alb = new awsx.lb.ApplicationLoadBalancer(`${config.generalTagName}-alb`, {
    name: `${config.generalTagName}-alb`,
    vpc: vpc,
    securityGroups: [securityGroupAlb],
    accessLogs,
    tags: {
        Name: `${config.generalTagName}-alb`,
        [config.generalTagName]: "shared",
    }
});

const targetGroupAlb = alb.createTargetGroup(`${config.generalTagName}-alb-tg`, {
    protocol: "HTTP",
    targetType: "instance",
    healthCheck: {
        healthyThreshold: 5,
        interval: 15,
        path: "/",
        timeout: 3,
        unhealthyThreshold: 2,
        matcher: "200"
    },
});

targetGroupAlb.createListener(`${config.generalTagName}-alb-listenerHttp`, {
    port: 80,
    protocol: "HTTP",
    defaultAction: {
        type: "redirect",
        redirect: {
            protocol: "HTTPS",
            port: "443",
            statusCode: "HTTP_301",
        },
    },
});

const listenerHttps = targetGroupAlb.createListener(`${config.generalTagName}-alb-listenerHttps`, {
    port: 443,
    protocol: "HTTPS",
    sslPolicy: "ELBSecurityPolicy-TLS-1-2-2017-01",
    certificateArn: config.certificateArn
});

createAliasRecord(config.targetDomain, alb);

if (['dev'].indexOf(config.stack) !== -1) {
    new aws.lb.ListenerCertificate(`${config.generalTagName}-alb-dev`, {
        listenerArn: listenerHttps.listener.arn,
        certificateArn: config.certificateArnDev
    });

    createAliasRecord(config.targetDomainDev, alb);
}

function createAliasRecord(targetDomain: string, alb: awsx.lb.ApplicationLoadBalancer): aws.route53.Record {
    const hostedZoneId = aws.route53.getZone({name: `${targetDomain}.`}, {async: true}).then(zone => zone.zoneId);
    return new aws.route53.Record(
        targetDomain,
        {
            name: `${targetDomain}.`,
            zoneId: hostedZoneId,
            type: aws.route53.RecordTypes.A,
            aliases: [
                {
                    name: alb.loadBalancer.dnsName,
                    zoneId: alb.loadBalancer.zoneId,
                    evaluateTargetHealth: true,
                },
            ],
        });
}

/**
 * Creating security groups
 */
const securityGroupSsh = new awsx.ec2.SecurityGroup(`${config.generalTagName}-ssh-sg`, {
    vpc,
    ingress: [
        {protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: ["0.0.0.0/0"]},
    ],
    egress: [
        {protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"]}
    ],
    tags: {
        Name: `${config.generalTagName}-ssh-sg`,
        [config.generalTagName]: "shared",
    }
});

const securityGroupFromAlb = new awsx.ec2.SecurityGroup(`${config.generalTagName}-fromalb-sg`, {
    vpc,
    ingress: [
        {protocol: "tcp", fromPort: 80, toPort: 80, sourceSecurityGroupId: securityGroupAlb.id}
    ],
    egress: [
        {protocol: "-1", fromPort: 0, toPort: 0, sourceSecurityGroupId: securityGroupAlb.id}
    ],
    tags: {
        Name: `${config.generalTagName}-fromalb-sg`,
        [config.generalTagName]: "shared",
    }
});

const securityGroupRedis = new awsx.ec2.SecurityGroup(`${config.generalTagName}-redis-sg`, {
    vpc,
    ingress: [
        {protocol: "tcp", fromPort: 6379, toPort: 6379, cidrBlocks: ["0.0.0.0/0"]},
    ],
    egress: [
        {protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"]}
    ],
    tags: {
        Name: `${config.generalTagName}-redis-sg`,
        [config.generalTagName]: "shared",
    }
});

const securityGroupMySQL = new awsx.ec2.SecurityGroup(`${config.generalTagName}-mysql-sg`, {
    vpc,
    ingress: [
        {protocol: "tcp", fromPort: 3306, toPort: 3306, cidrBlocks: ["0.0.0.0/0"]},
    ],
    egress: [
        {protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"]}
    ],
    tags: {
        Name: `${config.generalTagName}-mysql-sg`,
        [config.generalTagName]: "shared",
    }
});

const securityGroupMongoDB = new awsx.ec2.SecurityGroup(`${config.generalTagName}-mongodb-sg`, {
    vpc,
    ingress: [
        {protocol: "tcp", fromPort: 27017, toPort: 27017, cidrBlocks: ["0.0.0.0/0"]},
    ],
    egress: [
        {protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"]}
    ],
    tags: {
        Name: `${config.generalTagName}-mongodb-sg`,
        [config.generalTagName]: "shared",
    }
});

/**
 * Creating KMS Keys
 */
let kmsMysql;

if (['production'].indexOf(config.stack) !== -1) {
    //If not show well in AWS console, only refresh policy
    const kmsDynamoDb = new aws.kms.Key(`${config.generalTagName}-kms-dynamodb`, {
        deletionWindowInDays: 30,
        customerMasterKeySpec: 'SYMMETRIC_DEFAULT',
        description: `${config.generalTagName}-kms-dynamodb`,
        tags: {
            Name: `${config.generalTagName}-kms-dynamodb`,
            [config.generalTagName]: "shared",
        }
    });

    new aws.kms.Alias(`${config.generalTagName}-kms-dynamodb-alias`, {
        name: `alias/${config.generalTagName}-kms-dynamodb`,
        targetKeyId: kmsDynamoDb.keyId
    });

    kmsMysql = new aws.kms.Key(`${config.generalTagName}-kms-mysql`, {
        deletionWindowInDays: 30,
        customerMasterKeySpec: 'SYMMETRIC_DEFAULT',
        description: `${config.generalTagName}-kms-mysql`,
        tags: {
            Name: `${config.generalTagName}-kms-mysql`,
            [config.generalTagName]: "shared",
        }
    });

    new aws.kms.Alias(`${config.generalTagName}-kms-mysql-alias`, {
        name: `alias/${config.generalTagName}-kms-mysql`,
        targetKeyId: kmsMysql.keyId
    });
}

/**
 * Creating VPC Endpoints
 */
if (['production'].indexOf(config.stack) !== -1) {
    async function getRouteTableIdForSubnet(subnetId) {
        let res = await aws.ec2.getRouteTable({
            subnetId: subnetId,
        });

        return res.routeTableId;
    }

    let routeTableIds = pulumi.all([vpc.publicSubnetIds, vpc.privateSubnetIds]).apply(subnetIds => {
        subnetIds = [].concat.apply([], subnetIds);
        return Promise.all(subnetIds.map(getRouteTableIdForSubnet));
    });

    new aws.ec2.VpcEndpoint(`${config.generalTagName}-vpc-endpoint-dynamodb`, {
        vpcId: vpc.id,
        routeTableIds: routeTableIds,
        serviceName: `com.amazonaws.${aws.config.region}.dynamodb`,
        tags: {
            Name: `${config.generalTagName}-vpc-endpoint-dynamodb`,
            [config.generalTagName]: "shared",
        }
    });
}

/**
 * Creating WAF
 */
if (['production'].indexOf(config.stack) !== -1) {
    const bucketWafLogsName = `${config.generalTagName}-waf-logs`;

    const bucketWafLogs = new aws.s3.Bucket(bucketWafLogsName, {
        bucket: bucketWafLogsName,
        acl: "private",
        tags: {
            Name: `${config.generalTagName}-waf-logs`,
            [config.generalTagName]: "shared",
        }
    });

    let policyJson = pulumi.all([config.accountId, bucketWafLogs.bucket]).apply(data => {
        let policyStr = fs.readFileSync('./waf/kinesis_policy.json', 'utf8')
            .replace(/rep_region/g, aws.config.region)
            .replace(/rep_accountid/g, data[0])
            .replace(/rep_bucket_name/g, data[1]);

        return Promise.resolve(JSON.parse(policyStr));
    });

    const firehoseRolePolicy = new aws.iam.Policy(`${config.generalTagName}-waf-firehose-role-policy`, {
        path: "/",
        policy: policyJson,
    });

    const firehoseRole = new aws.iam.Role(`${config.generalTagName}-firehose-role`, {
        assumeRolePolicy: {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {
                        "Service": "firehose.amazonaws.com"
                    },
                    "Effect": "Allow",
                    "Sid": ""
                }
            ]
        },
        tags: {
            Name: `${config.generalTagName}-firehose-role`,
            [config.generalTagName]: "shared",
        }
    });

    new aws.iam.RolePolicyAttachment(`${config.generalTagName}-firehose-role-attach`, {
        role: firehoseRole.name,
        policyArn: firehoseRolePolicy.arn,
    });

    const firehoseDeliveryStream = new aws.kinesis.FirehoseDeliveryStream(`${config.generalTagName}-firehose-s3`, {
        name: `aws-waf-logs-${config.generalTagName}-backend`,
        destination: "extended_s3",
        extendedS3Configuration: {
            roleArn: firehoseRole.arn,
            bufferSize: 5,
            bufferInterval: 300,
            compressionFormat: 'GZIP',
            bucketArn: bucketWafLogs.arn
        },
        tags: {
            Name: `aws-waf-logs-${config.generalTagName}-backend`,
            [config.generalTagName]: "shared",
        }
    });

    const waf = new aws.wafv2.WebAcl(`${config.generalTagName}-acl-backend`, {
        name: `${config.generalTagName}-acl-backend`,
        defaultAction: {
            allow: {},
        },
        rules: [
            JSON.parse(fs.readFileSync('./waf/01_maximum_number_of_requests.json', 'utf8')),
            JSON.parse(fs.readFileSync('./waf/02_AWSManagedRulesAmazonIpReputationList.json', 'utf8')),
            JSON.parse(fs.readFileSync('./waf/03_AWSManagedRulesAnonymousIpList.json', 'utf8')),
            JSON.parse(fs.readFileSync('./waf/05_AWSManagedRulesKnownBadInputsRuleSet.json', 'utf8')),
            JSON.parse(fs.readFileSync('./waf/06_AWSManagedRulesLinuxRuleSet.json', 'utf8')),
        ],
        scope: "REGIONAL",
        visibilityConfig: {
            cloudwatchMetricsEnabled: true,
            metricName: `${config.generalTagName}-acl-backend`,
            sampledRequestsEnabled: true,
        },
        tags: {
            Name: `${config.generalTagName}-acl-backend`,
            [config.generalTagName]: "shared",
        }
    });

    new aws.wafv2.WebAclLoggingConfiguration(`${config.generalTagName}-acl-logs`, {
        logDestinationConfigs: [firehoseDeliveryStream.arn],
        resourceArn: waf.arn
    });
}


/**
 * Creating Aurora instances
 */
if (['production'].indexOf(config.stack) !== -1) {
    const dbPasswordRoot = new random.RandomPassword(`${config.generalTagName}-aurora-password-root`, {
        length: 30,
        special: false
    });

    const subnetGroupAurora = new aws.docdb.SubnetGroup(`${config.generalTagName}-aurora-subgrup`, {
        subnetIds: vpc.publicSubnetIds,
        tags: {
            Name: `${config.generalTagName}-aurora-subgrup`,
            [config.generalTagName]: "shared",
        }
    });

    const auroraEngine = 'aurora-mysql';

    const defaultCluster = new aws.rds.Cluster(`${config.generalTagName}-aurora-cluster`, {
        clusterIdentifier: `${config.generalTagName}-aurora-cluster`,
        backupRetentionPeriod: 3,
        databaseName: "app1",
        engine: auroraEngine,
        engineMode: "provisioned",
        engineVersion: "5.7.mysql_aurora.2.10.0",
        dbSubnetGroupName: subnetGroupAurora.name,
        vpcSecurityGroupIds: [securityGroupMySQL.securityGroup.id],
        masterUsername: "admin",
        masterPassword: dbPasswordRoot.result,
        skipFinalSnapshot: true,
        storageEncrypted: true,
        kmsKeyId: kmsMysql.arn,
        preferredBackupWindow: "00:00-05:00",
    });

    for (const range = {value: 0}; range.value < config.auroraNodes; range.value++) {
        new aws.rds.ClusterInstance(`${config.generalTagName}-aurora-instance-${range.value}`, {
            identifier: `${config.generalTagName}-aurora-instance-${range.value}`,
            clusterIdentifier: defaultCluster.id,
            instanceClass: config.auroraInstanceType,
            engine: auroraEngine,
            publiclyAccessible: true,
            engineVersion: defaultCluster.engineVersion,
        })
    }

    dbPasswordRoot.result.apply(x => console.log(`SQL: ${x}`));
}


/**
 * Creating Redis instances
 */
if (['production'].indexOf(config.stack) !== -1) {
    const subnetGroupRedis = new aws.elasticache.SubnetGroup(`${config.generalTagName}-redis-subgrup`, {
        name: `${config.generalTagName}-redis-subgrup`,
        subnetIds: vpc.privateSubnetIds
    });

    new aws.elasticache.ReplicationGroup(`${config.generalTagName}-redis-cluster`, {
        replicationGroupDescription: `${config.generalTagName}-redis-cluster`,
        engine: "redis",
        engineVersion: "5.0.6",
        nodeType: config.redisInstanceType,
        numberCacheClusters: config.redisNodes,
        snapshotRetentionLimit: 0,
        subnetGroupName: subnetGroupRedis.name,
        parameterGroupName: "default.redis5.0",
        securityGroupIds: [securityGroupRedis.securityGroup.id],
        port: 6379,
        tags: {
            Name: `${config.generalTagName}-redis`,
            [config.generalTagName]: "shared",
        }
    });
}


/**
 * Creating EC2 instances
 */
const amiId = aws.ec2.getAmi({
    filters: [
        {
            name: "name",
            values: ["CentOS 7.9*"],
        },
        {
            name: "architecture",
            values: ["x86_64"],
        }
    ],
    owners: ["125523088429"],

    mostRecent: true
}, {async: true}).then(ami => ami.id);

const userData = fs.readFileSync('./script.sh', 'utf8');

const ec2Key = new aws.ec2.KeyPair(`${config.generalTagName}-keypair`, {
    keyName: config.keyName,
    publicKey: fs.readFileSync('instance_user_public.pem', 'utf8')
});

let vpcSecurityGroupIds = [
    securityGroupSsh.securityGroup.id,
    securityGroupFromAlb.securityGroup.id
];

if (['production'].indexOf(config.stack) === -1) {
    vpcSecurityGroupIds.push(securityGroupRedis.securityGroup.id);
    vpcSecurityGroupIds.push(securityGroupMySQL.securityGroup.id);
    vpcSecurityGroupIds.push(securityGroupMongoDB.securityGroup.id);
}

const webserver = new aws.ec2.Instance(`${config.generalTagName}-webserver`, {
    instanceType: config.webserverInstanceType,
    ami: amiId,
    subnetId: pulumi.output(vpc.publicSubnetIds)[0].apply(x => x.toString()),
    vpcSecurityGroupIds,
    keyName: ec2Key.keyName,
    userData: userData,
    tags: {
        Name: `${config.generalTagName}-webserver`,
        [config.generalTagName]: "shared",
    }
});

new aws.lb.TargetGroupAttachment(`${config.generalTagName}-alb-attach`, {
    targetGroupArn: targetGroupAlb.targetGroup.arn,
    targetId: webserver.id,
    port: 80,
});