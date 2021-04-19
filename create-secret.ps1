<#
  .SYNOPSIS
  Creates or updates a secret in Secrets Manager for EC2 Instances, EC2 Auto-Scaling Groups, EC2 Key Pairs, RDS databases or on-premise databases.

  .DESCRIPTION
  This script validates the set of parameters passed and uses the AWS CLI to create or update a secret in Secrets Manager.

  .PARAMETER Region
  Must be a valid AWS region for the provided account. Attempt to determine this from the ARN if it is not supplied.

  .PARAMETER AccountID Perform a lookup to ensure that the configured account matches the account for which credentials are to be created.

  .PARAMETER ProfileName Use this profile for AWS CLI calls.

  .PARAMETER Type EC2Instance, EC2ASG, EC2KeyPair, RDSCluster, RDSInstance, or OnPremiseDatabase.

  .PARAMETER SecretType SSH, WinRM or Database. Required for Auto-Scaling Groups.

  .PARAMETER Description Free text.

  .PARAMETER ARN Must be valid. Mandatory, except for OnPremiseDatabases.

  .PARAMETER Environment Prod, PS, Dev, Testing, Staging, Mixed, or NonProd.

  .PARAMETER Username Required for EC2 Instance, EC2 ASG, RDSCluster, RDSInstance, and OnPremiseDatabase. Ignored for EC2 Key Pairs.

  .PARAMETER Password May be required in some cases if there's no private key - think about this.

  .PARAMETER Engine Required for RDSClusters, RDSInstances or OnPremiseDatabases.

  .PARAMETER DBHost Required for RDSClusters, RDSInstances or OnPremiseDatabases. Must be a valid hostname or IP address. DNS lookup may not work here.

  .PARAMETER DBPort Required for RDSClusters, RDSInstances or OnPremiseDatabases. Must be numeric, from 1 to 65535.

  .PARAMETER DBName Required for RDSClusters, RDSInstances or OnPremiseDatabases.

  .PARAMETER PrivateKey May be required in some cases if there's no password - think about this.

  .PARAMETER PrivateKeyPassword Can we check a supplied PrivateKey to see if the public key can be determined?

  .PARAMETER EscalationMethod Optional. There is probably no way to determine if this is correct.

  .PARAMETER EscalationUsername Optional in some cases. Is it ever mandatory for a specified EscalationMethod?

  .PARAMETER EscalationPassword Optional in some cases. Is it ever mandatory for a specified EscalationMethod?

  .PARAMETER Notes Any sensitive information you wish to store with the secret.

  .PARAMETER Force Force updates to secrets that already exist.

  .INPUTS
  None. You cannot pipe objects to this script.

  .OUTPUTS
  System.String. This script outputs the Secrets Manager secret ID.

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "EC2Instance" -Description "My EC2 Instance" -ARN "arn:aws:ec2:us-east-1:012345678901:instance/i-0123456789abcdef0" -Environment "Prod" -Username "ec2-user"

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "EC2ASG" -Description "My EC2 Auto-Scaling Group" -ARN "arn:aws:autoscaling:us-east-1:012345678901:autoScalingGroup:01234567-890a-1234-5678-9abcdef01234:autoScalingGroupName/my-ec2-asg" -Environment "Staging" -Username "Administrator" -Password 'rE0qU0uY2mY8mM6k'

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "EC2KeyPair" -Description "My EC2 Key Pair" -ARN "arn:aws:ec2:us-east-1:162174280605:key-pair/my-ec2-key-pair" -Environment "PS" -PrivateKey "-----BEGIN RSA PRIVATE KEY-----\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000000000000\n0000000000000000000000000000000000000000000000000000000000000000000=\n-----END RSA PRIVATE KEY-----"

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "RDSCluster" -Description "My RDS Cluster" -ARN "arn:aws:rds:us-east-1:012345678901:cluster:my-rds-cluster" -Environment "Dev" -Username "admin" -Password 'xY2kU1kA4vB3lQ4e' -Engine "mysql" -DBHost "my-rds-clustercluster.cluster-012345678901.us-east-1.rds.amazonaws.com" -DBPort 3306 -DBName "mydatabase"

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "RDSInstance" -Description "My RDS Instance" -ARN "arn:aws:rds:us-east-1:012345678901:db:my-rds-instance" -Environment "Mixed" -Username "admin" -Password 'gG7fY7cY8hZ9gU9y' -Engine "oracle" -DBHost "my-rds-instance.012345678901.us-east-1.rds.amazonaws.com" -DBPort 1521 -DBName "mydatabase"

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "us-east-1" -AccountID 012345678901 -ProfileName "default" -Type "OnPremiseDatabase" -Description "My on-premise database" -Environment "NonProd" -Username "admin" -Password 'lV3zY1mZ3hA7kP0a' -Engine "sqlserver" -DBHost "10.13.16.19" -DBPort 1433 -DBName "mydatabase"
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern("[a-zA-Z0-9\-]+")]
    [String]
    $Region = "us-east-1",
    [Parameter(Mandatory = $true)]
    [ValidatePattern("[0-9]{12}")]
    [String]
    $AccountID,
    [Parameter(Mandatory = $false)]
    [String]
    $ProfileName = "default",
    [Parameter(Mandatory = $true)]
    [ValidateSet("EC2Instance", "EC2ASG", "EC2KeyPair", "RDSCluster", "RDSInstance", "OnPremiseDatabase")]
    [String]
    $Type,
    [Parameter(Mandatory = $false)]
    [ValidateSet("SSH", "WinRM", "Database")]
    [String]
    $SecretType,
    [Parameter(Mandatory = $false)]
    [String]
    $Description,
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^arn:[^:\n]*:[^:\n]*:[^:\n]*:[^:\n]*:[^:\/\n]*[:\/]?.*$")]
    [String]
    $ARN,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Prod", "PS", "Dev", "Testing", "Staging", "Mixed", "NonProd")]
    [String]
    $Environment,
    [Parameter(Mandatory = $false)]
    [String]
    $Username,
    [Parameter(Mandatory = $false)]
    [String]
    $Password,
    [Parameter(Mandatory = $false)]
    [ValidateSet("mariadb", "mysql", "postgres", "oracle", "sqlserver", "neptune")]
    [String]
    $Engine,
    [Parameter(Mandatory = $false)]
    [String]
    $DBHost,
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 65535)]
    [int]
    $DBPort,
    [Parameter(Mandatory = $false)]
    [String]
    $DBName,
    [Parameter(Mandatory = $false)]
    [String]
    $PrivateKey,
    [Parameter(Mandatory = $false)]
    [String]
    $PrivateKeyPassword,
    [Parameter(Mandatory = $false)]
    [ValidateSet("sudo", "su", "pbrun", "pfexec", "dzdo", "pmrun", "runas", "enable", "doas", "ksu", "machinectl", "sesu")]
    [String]
    $EscalationMethod = "sudo",
    [Parameter(Mandatory = $false)]
    [String]
    $EscalationUsername,
    [Parameter(Mandatory = $false)]
    [String]
    $EscalationPassword,
    [Parameter(Mandatory = $false)]
    [String]
    $Notes,
    [Parameter(Mandatory = $false)]
    [Bool]
    $Force = $false
)

$Response = aws --region "$($Region)" --profile "$($ProfileName)" sts get-caller-identity | ConvertFrom-Json
if (-Not($Response.Account -eq $AccountID)) {
    Write-Error "The specified account ID does not match the AWS CLI profile in use."
    Return $false
}

$SecretNamePrefix = "eswcm-"

$SecretUpdateTitle    = 'A secret for this entity already exists'
$SecretUpdateQuestion = 'Are you sure you want to update the secret?'

$SecretUpdateChoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$SecretUpdateChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$SecretUpdateChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

$SecretStringObject = [PSCustomObject]@{}

$InternalARN = $ARN -replace '[^a-zA-Z0-9 :_@\/\+\=\.\-]', ''

switch ($Type) {
    "EC2Instance" {
        if ($InternalARN -eq "") {
            Write-Error "The ARN cannot be empty for an EC2 Instance."
            Return $false
        }
        $EC2InstanceID = $InternalARN -replace '^.*\/'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" ec2 describe-instances --instance-ids "$($EC2InstanceID)" | ConvertFrom-Json
        if ($Response.Reservations.Count -eq 0) {
            Write-Error "The instance was not found using this region and profile name."
            Return $false
        }
        if ($Username -eq "") {
            Write-Error "A username is required for an EC2 instance."
            Return $false
        }
        if ($Response.Reservations[0].Instances[0].Platform -eq "windows") {
            $SecretType = "SSH"
        } else {
            $SecretType = "WinRM"
        }
        if ($Password -eq "" -and $PrivateKey -eq "") {
            $EC2KeyPairSecretName = "$($SecretNamePrefix)$($Response.Reservations[0].Instances[0].KeyName)"
            $SecretsManagerResponse = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager describe-secret --secret-id "$($EC2KeyPairSecretName)" | ConvertFrom-Json
            if (-Not($SecretsManagerResponse.Name -eq $EC2KeyPairSecretName)) {
                Write-Error "You must maintain the secret for the EC2 Key Pair to maintain a secret for an EC2 instance without a password or private key."
                Return $false
            }
        }
        if (-Not($Engine -eq "")) {
            Write-Warning "The database engine is ignored for EC2 instances."
        }
        if (-Not($DBHost -eq "")) {
            Write-Warning "The database host is ignored for EC2 instances."
        }
        if (-Not($DBPort -eq "")) {
            Write-Warning "The database port is ignored for EC2 instances."
        }
        if (-Not($DBName -eq "")) {
            Write-Warning "The database name is ignored for EC2 instances."
        }
        if ($PrivateKey -like "*ENCRYPTED*" -and $PrivateKeyPassword -eq "") {
            Write-Error "You must supply the password for a password-protected private key."
            Return $False
        }
        $SecretName = "$($SecretNamePrefix)$($Response.Reservations[0].Instances[0].InstanceId)"
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'username' -Value $Username
        if (-Not($Password -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'password' -Value $Password
        }
        if (-Not($PrivateKey -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'privatekey' -Value $PrivateKey
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'privatekeypassword' -Value $PrivateKeyPassword
        }
        if (-Not($EsclationMethod -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'escalationmethod' -Value $EscalationMethod
        }
        if (-Not($EscalationUsername -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'escalationusername' -Value $EscalationUsername
        }
        if (-Not($EscalationPassword -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'escalationpassword' -Value $EscalationPassword
        }
        if (-Not($Notes -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'notes' -Value $Notes
        }
        Break
    }
    "EC2ASG" {
        if ($InternalARN -eq "") {
            Write-Error "The ARN cannot be empty for an EC2 Auto Scaling Group."
            Return $false
        }
        $EC2ASGName = $InternalARN -replace '^.*\/'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$($EC2ASGName)" | ConvertFrom-Json
        If (-Not($Response.AutoScalingGroups[0].AutoScalingGroupName -eq $EC2ASGName)) {
            Write-Error "The Auto Scaling Group was not found using this region and profile name."
            Return $false
        }
        if ($Username -eq "") {
            Write-Error "A username is required for an EC2 Auto Scaling Group."
            Return $false
        }
        if ($SecretType -eq "") {
            Write-Error "A SecretType is required for an EC2 Auto Scaling Group. Choose SSH for Linux instances and WinRM for Windows instances."
            Return $false
        }
        if ($Password -eq "" -and $PrivateKey -eq "") {
            if ($Response.AutoScalingGroups[0].LaunchConfigurationName) {
                $LaunchConfigurationResponse = aws --region "$($Region)" --profile "$($ProfileName)" autoscaling describe-launch-configurations --launch-configuration-names "$($Response.AutoScalingGroups[0].LaunchConfigurationName)" | ConvertFrom-Json
                $EC2KeyPairName = $LaunchConfigurationResponse.LaunchConfigurations[0].KeyName
            } elseif ($Response.AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId -and $Response.AutoScalingGroups[0].LaunchTemplate.Version) {
                $LaunchTemplateResponse = aws --region "$($Region)" --profile "$($ProfileName)" ec2 describe-launch-template-versions --launch-template-id "$($Response.AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId)" --versions "$($Response.AutoScalingGroups[0].LaunchTemplate.Version)" | ConvertFrom-Json
                $EC2KeyPairName = $LaunchTemplateResponse.LaunchTemplateVersions[0].LaunchTemplateData.KeyName
            }
            if (-Not($EC2KeyPairName)) {
                Write-Error "Could not find the EC2 Key Pair associated with the Auto Scaling Group. You must supply a password or a private key."
                Return $false
            } else {
                $EC2KeyPairSecretName = "$($SecretNamePrefix)$($EC2KeyPairName)"
                $SecretsManagerResponse = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager describe-secret --secret-id "$($EC2KeyPairSecretName)" | ConvertFrom-Json
                if (-Not($SecretsManagerResponse.Name -eq $EC2KeyPairSecretName)) {
                    Write-Error "You must maintain the secret for the EC2 Key Pair to maintain a secret for an EC2 Auto Scaling Group without a password or private key."
                    Return $false
                }
            }
        }
        if (-Not($Engine -eq "")) {
            Write-Warning "The database engine is ignored for EC2 Auto Scaling Groups."
        }
        if (-Not($DBHost -eq "")) {
            Write-Warning "The database host is ignored for EC2 Auto Scaling Groups."
        }
        if (-Not($DBPort -eq "")) {
            Write-Warning "The database port is ignored for EC2 Auto Scaling Groups."
        }
        if (-Not($DBName -eq "")) {
            Write-Warning "The database name is ignored for EC2 Auto Scaling Groups."
        }
        if ($PrivateKey -like "*ENCRYPTED*" -and $PrivateKeyPassword -eq "") {
            Write-Error "You must supply the password for a password-protected private key."
            Return $False
        }
        $SecretName = "$($SecretNamePrefix)$($Response.AutoScalingGroups[0].AutoScalingGroupName)"
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'username' -Value $Username
        if (-Not($Password -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'password' -Value $Password
        }
        if (-Not($PrivateKey -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'privatekey' -Value $PrivateKey
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'privatekeypassword' -Value $PrivateKeyPassword
        }
        if (-Not($EscalationMethod -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'escalationmethod' -Value $EscalationMethod
        }
        if (-Not($EscalationUsername -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'escalationusername' -Value $EscalationUsername
        }
        if (-Not($EscalationPassword -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'escalationpassword' -Value $EscalationPassword
        }
        if (-Not($Notes -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'notes' -Value $Notes
        }
        Break
    }
    "EC2KeyPair" {
        if ($InternalARN -eq "") {
            Write-Error "The ARN cannot be empty for an EC2 Key Pair."
            Return $false
        }
        $EC2KeyPairName = $InternalARN -replace '^.*\/'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" ec2 describe-key-pairs --key-name "$($EC2KeyPairName)" | ConvertFrom-Json
        if (-Not($Response.KeyPairs.KeyName -eq $EC2KeyPairName)) {
            Write-Error "The EC2 Key Pair was not found using this region and profile name."
            Return $false
        }
        if (-Not($Username -eq "")) {
            Write-Warning "The username is ignored for EC2 Key Pairs."
        }
        if (-Not($Password -eq "")) {
            Write-Warning "The password is ignored for EC2 Key Pairs."
        }
        if (-Not($SecretType -eq "")) {
            Write-Warning "The SecretType is ignored for EC2 Key Pairs."
        }
        if (-Not($Engine -eq "")) {
            Write-Warning "The database engine is ignored for EC2 Key Pairs."
        }
        if (-Not($DBHost -eq "")) {
            Write-Warning "The database host is ignored for EC2 Key Pairs."
        }
        if (-Not($DBPort -eq "")) {
            Write-Warning "The database port is ignored for EC2 Key Pairs."
        }
        if (-Not($DBName -eq "")) {
            Write-Warning "The database name is ignored for EC2 Key Pairs."
        }
        if ($PrivateKey -eq "") {
            Write-Error "The private key is required for an EC2 Key Pair."
            Return $false
        }
        if ($PrivateKey -like "*ENCRYPTED*" -and $PrivateKeyPassword -eq "") {
            Write-Error "You must supply the password for a password-protected private key."
            Return $False
        }
        $SecretName = "$($SecretNamePrefix)$($Response.KeyPairs.KeyName)"
        $SecretType = "SSH"
        if (-Not($PrivateKey -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'privatekey' -Value $PrivateKey
        }
        if ($PrivateKey -like "*ENCRYPTED*" -and -Not($PrivateKeyPassword -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'privatekeypassword' -Value $PrivateKeyPassword
        }
        if (-Not($EscalationMethod -eq "" -or $EscalationMethod -eq "sudo")) {
            Write-Warning "The escalation method is ignored for an EC2 Key Pair."
        }
        if (-Not($EscalationUsername -eq "")) {
            Write-Warning "The escalation username is ignored for an EC2 Key Pair."
        }
        if (-Not($EscalationPassword -eq "")) {
            Write-Warning "The escalation password is ignored for an EC2 Key Pair."
        }
        if (-Not($Notes -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'notes' -Value $Notes
        }
        Break
    }
    "RDSCluster" {
        if ($InternalARN -eq "") {
            Write-Error "The ARN cannot be empty for an RDS Cluster."
            Return $false
        }
        $RDSClusterName = $InternalARN -replace '^.*\:'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" rds describe-db-clusters --db-cluster-identifier "$($RDSClusterName)" | ConvertFrom-Json
        if (-Not($Response.DBClusters.DBClusterIdentifier -eq $RDSClusterName)) {
            Write-Error "The RDS database was not found using this region and profile name."
            Return $false
        }
        if (-Not($Username -eq "")) {
            Write-Warning "The username is automatically populated for an RDS Cluster."
        }
        if ($Password -eq "") {
            Write-Error "A password is required for an RDS Cluster."
            Return $false
        }
        if (-Not($SecretType -eq "")) {
            Write-Warning "The SecretType is ignored for RDS Clusters."
        }
        if (-Not($Engine -eq "")) {
            Write-Warning "The database engine is automatically determined for an RDS Cluster."
        }
        if (-Not($DBHost -eq "")) {
            Write-Warning "The database host is automatically determined for an RDS Cluster."
        }
        if (-Not($DBPort -eq "")) {
            Write-Warning "The database port is automatically determined for an RDS Cluster."
        }
        if (-Not($DBName -eq "")) {
            Write-Warning "The database name is automatically determined for an RDS Cluster."
        }
        if (-Not($PrivateKey -eq "")) {
            Write-Warning "The private key is ignored for an RDS Cluster."
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            Write-Warning "The private key password is ignored for an RDS Cluster."
        }
        if (-Not($EscalationMethod -eq "" -or $EscalationMethod -eq "sudo")) {
            Write-Warning "The escalation method is ignored for an RDS Cluster."
        }
        if (-Not($EscalationUsername -eq "")) {
            Write-Warning "The escalation username is ignored for an RDS Cluster."
        }
        if (-Not($EscalationPassword -eq "")) {
            Write-Warning "The escalation password is ignored for an RDS Cluster."
        }
        $SecretName = "$($SecretNamePrefix)$($Response.DBClusters.DBClusterIdentifier)"
        $SecretType = "Database"
        if ($Response.DBClusters[0].MasterUsername) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'username' -Value $Response.DBClusters[0].MasterUsername
        }
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'password' -Value $Password
        if ($Response.DBClusters[0].Engine) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'engine' -Value $Response.DBClusters[0].Engine
        }
        if ($Response.DBClusters[0].Endpoint) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'host' -Value $Response.DBClusters[0].Endpoint
        }
        if ($Response.DBClusters[0].Port) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'port' -Value $Response.DBClusters[0].Port
        }
        if ($Response.DBClusters[0].DatabaseName) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'dbname' -Value $Response.DBClusters[0].DatabaseName
        }
        if (-Not($Notes -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'notes' -Value $Notes
        }
        Break
    }
    "RDSInstance" {
        if ($InternalARN -eq "") {
            Write-Error "The ARN cannot be empty for an RDS Instance."
            Return $false
        }
        $RDSInstanceName = $InternalARN -replace '^.*\:'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" rds describe-db-instances --db-instance-identifier "$($RDSInstanceName)" | ConvertFrom-Json
        if (-Not($Response.DBInstances.DBInstanceIdentifier -eq $RDSInstanceName)) {
            Write-Error "The RDS database was not found using this region and profile name."
            Return $false
        }
        if (-Not($Username -eq "")) {
            Write-Warning "The username is automatically populated for an RDS Instance."
        }
        if ($Password -eq "") {
            Write-Error "A password is required for an RDS Instance."
            Return $false
        }
        if (-Not($SecretType -eq "")) {
            Write-Warning "The SecretType is ignored for RDS Instances."
        }
        if (-Not($Engine -eq "")) {
            Write-Warning "The database engine is automatically determined for an RDS Instance."
        }
        if (-Not($DBHost -eq "")) {
            Write-Warning "The database host is automatically determined for an RDS Instance."
        }
        if (-Not($DBPort -eq "")) {
            Write-Warning "The database port is automatically determined for an RDS Instance."
        }
        if (-Not($DBName -eq "")) {
            Write-Warning "The database name is automatically determined for an RDS Instance."
        }
        if (-Not($PrivateKey -eq "")) {
            Write-Warning "The private key is ignored for an RDS Instance."
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            Write-Warning "The private key password is ignored for an RDS Instance."
        }
        if (-Not($EscalationMethod -eq "" -or $EscalationMethod -eq "sudo")) {
            Write-Warning "The escalation method is ignored for an RDS Instance."
        }
        if (-Not($EscalationUsername -eq "")) {
            Write-Warning "The escalation username is ignored for an RDS Instance."
        }
        if (-Not($EscalationPassword -eq "")) {
            Write-Warning "The escalation password is ignored for an RDS Instance."
        }
        $SecretName = "$($SecretNamePrefix)$($Response.DBInstances.DBInstanceIdentifier)"
        $SecretType = "Database"
        if ($Response.DBInstances[0].MasterUsername) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'username' -Value $Response.DBInstances[0].MasterUsername
        }
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'password' -Value $Password
        if ($Response.DBInstances[0].Engine) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'engine' -Value $Response.DBInstances[0].Engine
        }
        if ($Response.DBInstances[0].Endpoint.Address) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'host' -Value $Response.DBInstances[0].Endpoint.Address
        }
        if ($Response.DBInstances[0].Endpoint.Port) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'port' -Value $Response.DBInstances[0].Endpoint.Port
        }
        if ($Response.DBInstances[0].DBName) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'dbname' -Value $Response.DBInstances[0].DBName
        }
        if (-Not($Notes -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'notes' -Value $Notes
        }
        Break
    }
    "OnPremiseDatabase" {
        if (-Not($InternalARN -eq "")) {
            Write-Warning "The ARN is not used for an on-premise database."
            Return $false
        }
        if ($Username -eq "") {
            Write-Error "A username is required for an on-premise database."
            Return $false
        }
        if ($Password -eq "") {
            Write-Error "A password is required for an on-premise database."
            Return $false
        }
        if (-Not($SecretType -eq "")) {
            Write-Warning "The SecretType is ignored for on-premise databases."
        }
        if ($Engine -eq "") {
            Write-Error "The database engine is required for an on-premise database."
            Return $false
        }
        if ($DBHost -eq "") {
            Write-Error "The database host is required for an on-premise database."
            Return $false
        }
        if ($DBPort -eq "") {
            Write-Error "The database port is required for an on-premise database."
            Return $false
        }
        if ($DBName -eq "") {
            Write-Error "The database name is required for an on-premise database."
            Return $false
        }
        if (-Not($PrivateKey -eq "")) {
            Write-Warning "The private key is ignored for an on-premise database."
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            Write-Warning "The private key is ignored for an on-premise database."
        }
        if (-Not($EscalationMethod -eq "" -or $EscalationMethod -eq "sudo")) {
            Write-Warning "The escalation method is ignored for an on-premise database."
        }
        if (-Not($EscalationUsername -eq "")) {
            Write-Warning "The escalation username is ignored for an on-premise database."
        }
        if (-Not($EscalationPassword -eq "")) {
            Write-Warning "The escalation password is ignored for an on-premise database."
        }
        Write-Warning "There is no resource validation performed for an on-premise database."
        $SecretName = "$($SecretNamePrefix)$($DBName)"
        $SecretType = "Database"
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'username' -Value $Username
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'password' -Value $Password
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'engine' -Value $Engine
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'host' -Value $DBHost
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'port' -Value $DBPort
        $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'dbname' -Value $DBName
        if (-Not($Notes -eq "")) {
            $SecretStringObject | Add-Member -MemberType NoteProperty -Name 'notes' -Value $Notes
        }
        Break
    }
}

$Response = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager describe-secret --secret-id "$($SecretName)" | ConvertFrom-Json
if ($Response.Name -eq $SecretName) {
    $SecretExists = $true
    if ($Force -eq $false) {
        $SecretUpdateDecision = $Host.UI.PromptForChoice($SecretUpdateTitle, $SecretUpdateQuestion, $SecretUpdateChoices, 1)
        if ($SecretUpdateDecision -eq 0) {
            Write-Output 'The secret value will be updated.'
        } else {
            Write-Output 'The secret value will not be updated.'
            Return $false
        }
    }
} else {
    $SecretExists = $false
}

$SecretString = ConvertTo-Json $SecretStringObject

Write-Output "Using the following JSON for the Secrets Manager secret value:"
Write-Output $SecretString

if ($SecretExists) {
    $SecretUpdate = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager update-secret --secret-id "$($SecretName)" --description "$($Description)" --secret-string "$($SecretString)" | ConvertFrom-Json
    aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager tag-resource --secret-id "$($SecretName)" --tags Key="AssetType",Value="$($Type)" Key="SecretType",Value="$($SecretType)" Key="ARN",Value="$($InternalARN)" Key="Environment",Value="$($Environment)"
    Return "Updated the secret named `"$($SecretUpdate.Name)`"."
} else {
    $SecretCreation = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager create-secret --name "$($SecretName)" --client-request-token "$([guid]::NewGuid())" --description "$($Description)" --secret-string "$($SecretString)" --tags Key="AssetType",Value="$($Type)" Key="SecretType",Value="$($SecretType)" Key="ARN",Value="$($InternalARN)" Key="Environment",Value="$($Environment)" | ConvertFrom-Json
    Return "Created a secret named `"$($SecretCreation.Name)`"."
}
