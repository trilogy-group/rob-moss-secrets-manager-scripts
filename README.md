# Rob Moss: Secrets Manager Scripts

This repository contains two PowerShell scripts.

## check-account-secrets.ps1

This PowerShell script checks a specified AWS account for secrets for EC2
Instances, EC2 Auto-Scaling Groups, EC2 Key Pairs, RDS Clusters and RDS
Instances.

The script does not yet validate secret properties or values for compliance with
the prescribed data model. It is assumed that the secrets will be created using
the below script.

### Usage of check-account-secrets.ps1

See ```Get-Help .\check-account-secrets.ps1```

## create-secret.ps1

This PowerShell script creates a secret for a specified resource, following the
prescribed data model.

### Usage of create-secret.ps1

See ```Get-Help .\create-secret.ps1```

Each Instance Needs to either have it's key stored seperately in Secrets, or have the authentication credentials saved within the EC2 Secret Itself. 

#### Creating A Key Secret
To creteate a Key Secret using the create-secret.ps1 script

```console
PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "EC2KeyPair" -Description "My EC2 Key Pair" -ARN "arn:aws:ec2:us-east-1:162174280605:key-pair/my-ec2-key-pair" -Environment "PS" -PrivateKey "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
```
#### Creating A Standlone / Spot EC2 Secret
To create an standalone EC2 Entry authenticated using a seperately stored key
```console
PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "EC2Instance" -Description "My EC2 Instance" -ARN "arn:aws:ec2:us-east-1:012345678901:instance/i-0123456789abcdef0" -Environment "Prod" -Username "ec2-user"
```

To create an standalone EC2 Entry authenticated using a password or a key without storing
```console
PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "EC2Instance" -Description "My EC2 Instance" -ARN "arn:aws:ec2:us-east-1:012345678901:instance/i-0123456789abcdef0" -Environment "Prod" -Username "ec2-user" -Password 'rE0qU0uY2mY8mM6k'
```

Or a Key
```console
PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "EC2Instance" -Description "My EC2 Instance" -ARN "arn:aws:ec2:us-east-1:012345678901:instance/i-0123456789abcdef0" -Environment "Prod" -Username "ec2-user" -PrivateKey "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
```

#### Creating an ASG Secret
For ASG, the same authentication requirements apply: Either a seperate key, or a password / key within the ASG Secret. 
To create an ASG Secret using a password:

```console
PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "EC2ASG" -Description "My EC2 Auto-Scaling Group" -ARN "arn:aws:autoscaling:us-east-1:012345678901:autoScalingGroup:01234567-890a-1234-5678-9abcdef01234:autoScalingGroupName/my-ec2-asg" -Environment "Staging" -Username "Administrator" -Password 'rE0qU0uY2mY8mM6k'
```
