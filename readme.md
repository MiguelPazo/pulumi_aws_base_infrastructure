This project is for deploy assets projects in aws. The credentials for jenkins are setter in the deploy script as environment variable.

### Params
```
pulumi config set aws:profile profile
pulumi config set aws:region region
pulumi config set generalTagName tagname
pulumi config set keyName ec2-user
pulumi config set rdsaz us-east-1a
pulumi config set targetDomain domain.com
pulumi config set referenceCerts pulumi/stack
```

### Configuration
For run, you have two options:

##### 1. Set enviroment variables:

```
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
```

##### 2. Create config file in %userprofile%/.aws
Check this guide:
```
https://www.pulumi.com/docs/intro/cloud-providers/aws/setup/
```

Then create access_token from pulumi and set as environment variable
```
PULUMI_ACCESS_TOKEN=
```
