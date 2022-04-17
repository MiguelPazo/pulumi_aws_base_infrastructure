/**
 * Created by Miguel Pazo (https://miguelpazo.com)
 */
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const configPulumi = new pulumi.Config();
export const stack = pulumi.getStack();

export const keyName: pulumi.Input<string> = configPulumi.get("keyName");
export const generalTagName = configPulumi.get("generalTagName");
export const numberOfNatGateways = configPulumi.getNumber("numberOfNatGateways");

export const webserverInstanceType = configPulumi.get("webserverInstanceType");

export const targetDomain = configPulumi.get("targetDomain");
export const targetDomainDev = configPulumi.get("targetDomainDev");

export const auroraInstanceType = configPulumi.get("auroraInstanceType");
export const auroraNodes = configPulumi.getNumber("auroraNodes");

export const redisInstanceType = configPulumi.get("redisInstanceType");
export const redisNodes = configPulumi.getNumber("redisNodes");

const current = aws.getCallerIdentity({});
export const accountId = current.then(current => current.accountId);

/**
 * Fetching certificate for target domain for ALB
 */
export const referenceCerts = configPulumi.get("referenceCerts");
export const certificates = new pulumi.StackReference(referenceCerts);

export const certificateArn = pulumi.output(certificates.getOutput(`result`).apply(x => targetDomain ? x[targetDomain] : null));
export const certificateArnDev = pulumi.output(certificates.getOutput(`result`).apply(x => targetDomainDev ? x[targetDomainDev] : null));
