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
