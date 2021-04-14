<#
  .SYNOPSIS
  Creates or updates a secret in Secrets Manager for EC2 Instances, EC2 Auto-Scaling Groups, EC2 Key Pairs, RDS databases or on-premise databases.

  .DESCRIPTION
  This script validates the set of parameters passed and uses the AWS Tools for PowerShell to create or update a secret in Secrets Manager.

  .PARAMETER Region
  Must be a valid AWS region for the provided account. Attempt to determine this from the ARN if it is not supplied.

  .PARAMETER AccountID Perform a lookup to ensure that the configured account matches the account for which credentials are to be created.

  .PARAMETER ProfileName Use this profile for AWS CLI calls.

  .PARAMETER Type EC2Instance, EC2ASG, EC2KeyPair, RDSCluster, RDSInstance, or OnPremiseDatabase.

  .PARAMETER Description Free text.

  .PARAMETER ARN Must be valid. Mandatory, except for OnPremiseDatabases.

  .PARAMETER Environment Production, Staging, QA, or Development.

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

  .PARAMETER Notes

  .INPUTS
  None. You cannot pipe objects to this script.

  .OUTPUTS
  System.String. This script outputs the Secrets Manager secret ID.

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "" -AccountID "" -ProfileName "" -Type "" -Description "" -ARN "" -Environment "" -Username "" -Password "" -Engine "" -DBHost "" -DBPort "" -DBName "" -PrivateKey "" -PrivateKeyPassword "" -EscalationMethod "" -EscalationUsername "" -EscalationPassword ""

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "" -AccountID "" -ProfileName "" -Type "" -Description "" -ARN "" -Environment "" -Username "" -Password "" -Engine "" -DBHost "" -DBPort "" -DBName "" -PrivateKey "" -PrivateKeyPassword "" -EscalationMethod "" -EscalationUsername "" -EscalationPassword ""

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "" -AccountID "" -ProfileName "" -Type "" -Description "" -ARN "" -Environment "" -Username "" -Password "" -Engine "" -DBHost "" -DBPort "" -DBName "" -PrivateKey "" -PrivateKeyPassword "" -EscalationMethod "" -EscalationUsername "" -EscalationPassword ""

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "" -AccountID "" -ProfileName "" -Type "" -Description "" -ARN "" -Environment "" -Username "" -Password "" -Engine "" -DBHost "" -DBPort "" -DBName "" -PrivateKey "" -PrivateKeyPassword "" -EscalationMethod "" -EscalationUsername "" -EscalationPassword ""

  .EXAMPLE
  PS> .\create-secret.ps1 -Region "" -AccountID "" -ProfileName "" -Type "" -Description "" -ARN "" -Environment "" -Username "" -Password "" -Engine "" -DBHost "" -DBPort "" -DBName "" -PrivateKey "" -PrivateKeyPassword "" -EscalationMethod "" -EscalationUsername "" -EscalationPassword ""
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet([RegionNames])]
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
    [String]
    $Description,
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^arn:(?P<Partition>[^:\n]*):(?P<Service>[^:\n]*):(?P<Region>[^:\n]*):(?P<AccountID>[^:\n]*):(?P<Ignore>(?P<ResourceType>[^:\/\n]*)[:\/])?(?P<Resource>.*)$")]
    [String]
    $ARN,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Production", "Staging", "QA", "Development")]
    [String]
    $Environment,
    [Parameter(Mandatory = $false)]
    [String]
    $Username,
    [Parameter(Mandatory = $false)]
    [String]
    $Password,
    [Parameter(Mandatory = $false)]
    [ValidateSet("mariadb", "mysql", "postgres", "oracle", "sqlserver")]
    [String]
    $Engine,
    [Parameter(Mandatory = $false)]
    [String]
    $DBHost,
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 65535)]
    [int]
    $DBPort = 3306,
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
    $EscalationPassword
)

Class RegionNames : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {
        $RegionNames = (aws ec2 describe-regions | ConvertFrom-Json).Regions.RegionName
        return [String[]] $RegionNames
    }
}

$Response = aws --region "$($Region)" --profile "$($ProfileName)" sts get-caller-identity | ConvertFrom-Json
if (-Not($Response.Account -eq $AccountID)) {
    Write-Error -Message "The specified account ID does not match the AWS CLI profile in use."
    Return $false
}

$SecretUpdateTitle    = 'A secret for this entity already exists'
$SecretUpdateQuestion = 'Are you sure you want to update the secret?'

$SecretUpdateChoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$SecretUpdateChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$SecretUpdateChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

$SecretStringObject = [PSCustomObject]@{}

switch ($Type) {
    "EC2Instance" {
        if ($ARN -eq "") {
            Write-Error -Message "The ARN cannot be empty for an EC2 Instance."
            Return $false
        }
        $EC2InstanceID = $ARN -replace '^.*\/'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" ec2 describe-instances --instance-ids "$($EC2InstanceID)" | ConvertFrom-Json
        if (-Not($Response.Reservations[0].Instances[0].InstanceId -eq $EC2InstanceID)) {
            Write-Error -Message "The instance was not found using this region and profile name."
            Return $false
        }
        if ($Username -eq "") {
            Write-Error -Message "A username is required for an EC2 instance."
            Return $false
        }
        if ($Password -eq "" -and $PrivateKey -eq "") {
            $EC2KeyPairSecretName = "escwm-$($Response.Reservations[0].Instances[0].KeyName)"
            $SecretsManagerResponse = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager --secret-id "$($EC2KeyPairSecretName)" | ConvertFrom-Json
            if (-Not($SecretsManagerResponse.Name -eq $EC2KeyPairSecretName)) {
                Write-Error -Message "You must maintain the secret for the EC2 Key Pair to maintain a secret for an EC2 instance without a password or private key."
                Return $false
            }
        }
        if (-Not($Engine -eq "")) {
            Write-Warning -Message "The database engine is ignored for EC2 instances."
        }
        if (-Not($DBHost -eq "")) {
            Write-Warning -Message "The database host is ignored for EC2 instances."
        }
        if (-Not($DBPort -eq "")) {
            Write-Warning -Message "The database port is ignored for EC2 instances."
        }
        if (-Not($DBName -eq "")) {
            Write-Warning -Message "The database name is ignored for EC2 instances."
        }
        if ($PrivateKey -like "*ENCRYPTED*" -and $PrivateKeyPassword -eq "") {
            Write-Error -Message "You must supply the password for a password-protected private key."
            Return $False
        }
        $SecretName = "eswcm-$($Response.Reservations[0].Instances[0].InstanceId)"
        $SecretStringObject.username = $Username
        if (-Not($Password -eq "")) {
            $SecretStringObject.password = $Password
        }
        if (-Not($PrivateKey -eq "")) {
            $SecretStringObject.privatekey = $PrivateKey
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            $SecretStringObject.privatekeypassword = $PrivateKeyPassword
        }
        if (-Not($EsclationMethod -eq "")) {
            $SecretStringObject.escalationmethod = $EscalationMethod
        }
        if (-Not($EscalationUsername -eq "")) {
            $SecretStringObject.escalationusername = $EscalationUsername
        }
        if (-Not($EsclationPassword -eq "")) {
            $SecretStringObject.escalationpassword = $EscalationPassword
        }
        if (-Not($Notes -eq "")) {
            $SecretStringObject.notes = $Notes
        }
        Break
    }
    "EC2ASG" {
        if ($ARN -eq "") {
            Write-Error -Message "The ARN cannot be empty for an EC2 Auto Scaling Group."
            Return $false
        }
        $EC2ASGName = $ARN -replace '^.*\/'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$($EC2ASGName)" | ConvertFrom-Json
        If (-Not($Response.AutoScalingGroups[0].AutoScalingGroupName -eq $EC2ASGName)) {
            Write-Error -Message "The Auto Scaling Group was not found using this region and profile name."
            Return $false
        }
        if ($Username -eq "") {
            Write-Error -Message "A username is required for an EC2 Auto Scaling Group."
            Return $false
        }
        if ($Password -eq "" -and $PrivateKey -eq "") {
            if ($Response.AutoScalingGroups[0].LaunchConfigurationName) {
                $LaunchConfigurationResponse = aws --region "$($Region)" --profile "$($ProfileName)" autoscaling describe-launch-configurations --launch-configuration-names "$($Response.AutoScalingGroups[0].LaunchConfigurationName)"
                $EC2KeyPairName = $LaunchConfigurationResponse.LaunchConfigurations[0].KeyName
            } elseif ($Response.AutoStaclingGroups[0].LaunchTemplate.LaunchTemplateId -and $Response.AutoStaclingGroups[0].LaunchTemplate.Version) {
                $LaunchTemplateResponse = aws --region "$($Region)" --profile "$($ProfileName)" autoscaling describe-launch-template-versions --launch-template-id "$($Response.AutoStaclingGroups[0].LaunchTemplate.LaunchTemplateId)" --versions "$($Response.AutoStaclingGroups[0].LaunchTemplate.Version)"
                $EC2KeyPairName = $LaunchTemplateResponse.LaunchTemplateVersions[0].LaunchTemplateData.KeyName
            }
            if (-Not($EC2KeyPairName)) {
                Write-Error -Message "Could not find the EC2 Key Pair associated with the Auto Scaling Group."
                Return $false
            } else {
                $EC2KeyPairSecretName = "eswcm-$($EC2KeyPairName)"
                $SecretsManagerResponse = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager --secret-id "$($EC2KeyPairSecretName)" | ConvertFrom-Json
                if (-Not($SecretsManagerResponse.Name -eq $EC2KeyPairSecretName)) {
                    Write-Error -Message "You must maintain the secret for the EC2 Key Pair to maintain a secret for an EC2 Auto Scaling Group without a password or private key."
                    Return $false
                }
            }
        }
        if (-Not($Engine -eq "")) {
            Write-Warning -Message "The database engine is ignored for EC2 Auto Scaling Groups."
        }
        if (-Not($DBHost -eq "")) {
            Write-Warning -Message "The database host is ignored for EC2 Auto Scaling Groups."
        }
        if (-Not($DBPort -eq "")) {
            Write-Warning -Message "The database port is ignored for EC2 Auto Scaling Groups."
        }
        if (-Not($DBName -eq "")) {
            Write-Warning -Message "The database name is ignored for EC2 Auto Scaling Groups."
        }
        if ($PrivateKey -like "*ENCRYPTED*" -and $PrivateKeyPassword -eq "") {
            Write-Error -Message "You must supply the password for a password-protected private key."
            Return $False
        }
        $SecretName = "eswcm-$($Response.AutoScalingGroups[0].AutoScalingGroupName)"
        $SecretStringObject.username = $Username
        if (-Not($Password -eq "")) {
            $SecretStringObject.password = $Password
        }
        if (-Not($PrivateKey -eq "")) {
            $SecretStringObject.privatekey = $PrivateKey
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            $SecretStringObject.privatekeypassword = $PrivateKeyPassword
        }
        if (-Not($EscalationMethod -eq "")) {
            $SecretStringObject.escalationmethod = $EscalationMethod
        }
        if (-Not($EscalationUsername -eq "")) {
            $SecretStringObject.escalationusername = $EscalationUsername
        }
        if (-Not($EscalationPassword -eq "")) {
            $SecretStringObject.escalationpassword = $EscalationPassword
        }
        if (-Not($Notes -eq "")) {
            $SecretStringObject.notes = $Notes
        }
        Break
    }
    "EC2KeyPair" {
        if ($ARN -eq "") {
            Write-Error -Message "The ARN cannot be empty for an EC2 Key Pair."
            Return $false
        }
        $EC2KeyPairName = $ARN -replace '^.*\/'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" ec2 describe-key-pairs --key-name "$($EC2KeyPairName)" | ConvertFrom-Json
        if (-Not($Response.KeyPairs.KeyName -eq $EC2KeyPairName)) {
            Write-Error -Message "The EC2 Key Pair was not found using this region and profile name."
            Return $false
        }
        if ($Username -eq "") {
            Write-Warning -Message "The username is ignored for EC2 Key Pairs."
        }
        if ($Password -eq "") {
            Write-Warning -Message "The password is ignored for EC2 Key Pairs."
        }
        if (-Not($Engine -eq "")) {
            Write-Warning -Message "The database engine is ignored for EC2 Key Pairs."
        }
        if (-Not($DBHost -eq "")) {
            Write-Warning -Message "The database host is ignored for EC2 Key Pairs."
        }
        if (-Not($DBPort -eq "")) {
            Write-Warning -Message "The database port is ignored for EC2 Key Pairs."
        }
        if (-Not($DBName -eq "")) {
            Write-Warning -Message "The database name is ignored for EC2 Key Pairs."
        }
        if ($PrivateKey -eq "") {
            Write-Error -Message "The private key is required for an EC2 Key Pair."
            Return $false
        }
        if ($PrivateKey -like "*ENCRYPTED*" -and $PrivateKeyPassword -eq "") {
            Write-Error -Message "You must supply the password for a password-protected private key."
            Return $False
        }
        $SecretName = "eswcm-$($Response.KeyPairs.KeyName)"
        if (-Not($PrivateKey -eq "")) {
            $SecretStringObject.privatekey = $PrivateKey
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            $SecretStringObject.privatekeypassword = $PrivateKeyPassword
        }
        if (-Not($EscalationMethod -eq "")) {
            $SecretStringObject.escalationmethod = $EscalationMethod
        }
        if (-Not($EscalationUsername -eq "")) {
            $SecretStringObject.escalationusername = $EscalationUsername
        }
        if (-Not($EscalationPassword -eq "")) {
            $SecretStringObject.escalationpassword = $EscalationPassword
        }
        if (-Not($Notes -eq "")) {
            $SecretStringObject.notes = $Notes
        }
        Break
    }
    "RDSCluster" {
        if ($ARN -eq "") {
            Write-Error -Message "The ARN cannot be empty for an RDS Cluster."
            Return $false
        }
        $RDSClusterName = $ARN -replace '^.*\/'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" describe-db-clusters --db-cluster-identifier "$($RDSClusterName)" | ConvertFrom-Json
        if (-Not($Response.DBClusters.DBClusterIdentifier -eq $RDSClusterName)) {
            Write-Error -Message "The RDS database was not found using this region and profile name."
        }
        if ($Username -eq "") {
            Write-Error -Message "A username is required for an RDS Cluster."
            Return $false
        }
        if ($Password -eq "") {
            Write-Error -Message "A password is required for an RDS Cluster."
            Return $false
        }
        if ($Engine -eq "") {
            Write-Error -Message "The database engine is required for an RDS Cluster."
            Return $false
        }
        if ($DBHost -eq "") {
            Write-Error -Message "The database host is required for an RDS Cluster."
            Return $false
        }
        if ($DBPort -eq "") {
            Write-Error -Message "The database port is required for an RDS Cluster."
            Return $false
        }
        if ($DBName -eq "") {
            Write-Error -Message "The database name is required for an RDS Cluster."
            Return $false
        }
        if (-Not($PrivateKey -eq "")) {
            Write-Warning -Message "The private key is ignored for an RDS Cluster."
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            Write-Warning -Message "The private key password is ignored for an RDS Cluster."
        }
        if (-Not($EscalationMethod -eq "")) {
            Write-Warning -Message "The escalation method is ignored for an RDS Cluster."
        }
        if (-Not($EscalationUsername -eq "")) {
            Write-Warning -Message "The escalation username is ignored for an RDS Cluster."
        }
        if (-Not($EscalationPassword -eq "")) {
            Write-Warning -Message "The escalation password is ignored for an RDS Cluster."
        }
        $SecretName = "eswcm-$($Response.DBClusters.DBClusterIdentifier)"
        $SecretStringObject.username = $Username
        $SecretStringObject.password = $Password
        $SecretStringObject.engine = $Engine
        $SecretStringObject.host = $DBHost
        $SecretStringObject.port = $DBPort
        $SecretStringObject.dbname = $DBName
        if (-Not($Notes -eq "")) {
            $SecretStringObject.notes = $Notes
        }
        Break
    }
    "RDSInstance" {
        if ($ARN -eq "") {
            Write-Error -Message "The ARN cannot be empty for an RDS Instance."
            Return $false
        }
        $RDSInstanceName = $ARN -replace '^.*\/'
        $Response = aws --region "$($Region)" --profile "$($ProfileName)" describe-db-instances --db-instance-identifier "$($RDSInstanceName)" | ConvertFrom-Json
        if (-Not($Response.DBInstances.DBInstanceIdentifier -eq $RDSInstanceName)) {
            Write-Error -Message "The RDS database was not found using this region and profile name."
        }
        if ($Username -eq "") {
            Write-Error -Message "A username is required for an RDS Instance."
            Return $false
        }
        if ($Password -eq "") {
            Write-Error -Message "A password is required for an RDS Instance."
            Return $false
        }
        if ($Engine -eq "") {
            Write-Error -Message "The database engine is required for an RDS Instance."
            Return $false
        }
        if ($DBHost -eq "") {
            Write-Error -Message "The database host is required for an RDS Instance."
            Return $false
        }
        if ($DBPort -eq "") {
            Write-Error -Message "The database port is required for an RDS Instance."
            Return $false
        }
        if ($DBName -eq "") {
            Write-Error -Message "The database name is required for an RDS Instance."
            Return $false
        }
        if (-Not($PrivateKey -eq "")) {
            Write-Warning -Message "The private key is ignored for an RDS Instance."
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            Write-Warning -Message "The private key password is ignored for an RDS Instance."
        }
        if (-Not($EscalationMethod -eq "")) {
            Write-Warning -Message "The escalation method is ignored for an RDS Instance."
        }
        if (-Not($EscalationUsername -eq "")) {
            Write-Warning -Message "The escalation username is ignored for an RDS Instance."
        }
        if (-Not($EscalationPassword -eq "")) {
            Write-Warning -Message "The escalation password is ignored for an RDS Instance."
        }
        $SecretName = "eswcm-$($Response.DBInstances.DBInstanceIdentifier)"
        $SecretStringObject.username = $Username
        $SecretStringObject.password = $Password
        $SecretStringObject.engine = $Engine
        $SecretStringObject.host = $DBHost
        $SecretStringObject.port = $DBPort
        $SecretStringObject.dbname = $DBName
        if (-Not($Notes -eq "")) {
            $SecretStringObject.notes = $Notes
        }
        Break
    }
    "OnPremiseDatabase" {
        if (-Not($ARN -eq "")) {
            Write-Warning -Message "The ARN is not used for an on-premise database."
            Return $false
        }
        if ($Username -eq "") {
            Write-Error -Message "A username is required for an on-premise database."
            Return $false
        }
        if ($Password -eq "") {
            Write-Error -Message "A password is required for an on-premise database."
            Return $false
        }
        if ($Engine -eq "") {
            Write-Error -Message "The database engine is required for an on-premise database."
            Return $false
        }
        if ($DBHost -eq "") {
            Write-Error -Message "The database host is required for an on-premise database."
            Return $false
        }
        if ($DBPort -eq "") {
            Write-Error -Message "The database port is required for an on-premise database."
            Return $false
        }
        if ($DBName -eq "") {
            Write-Error -Message "The database name is required for an on-premise database."
            Return $false
        }
        if (-Not($PrivateKey -eq "")) {
            Write-Warning -Message "The private key is ignored for an on-premise database."
        }
        if (-Not($PrivateKeyPassword -eq "")) {
            Write-Warning -Message "The private key is ignored for an on-premise database."
        }
        if (-Not($EscalationMethod -eq "")) {
            Write-Warning -Message "The escalation method is ignored for an on-premise database."
        }
        if (-Not($EscalationUsername -eq "")) {
            Write-Warning -Message "The escalation username is ignored for an on-premise database."
        }
        if (-Not($EscalationPassword -eq "")) {
            Write-Warning -Message "The escalation password is ignored for an on-premise database."
        }
        Write-Warning -Message "There is no resource validation performed for an on-premise database."
        $SecretName = "eswcm-$($DBName)"
        $SecretStringObject.username = $Username
        $SecretStringObject.password = $Password
        $SecretStringObject.engine = $Engine
        $SecretStringObject.host = $DBHost
        $SecretStringObject.port = $DBPort
        $SecretStringObject.dbname = $DBName
        if (-Not($Notes -eq "")) {
            $SecretStringObject.notes = $Notes
        }
        Break
    }
}

$Response = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager describe-secret --secret-id "$($SecretName)" | ConvertFrom-Json
if ($Response.Name -eq $SecretName) {
    $SecretExists = $true
    $SecretUpdateDecision = $Host.UI.PromptForChoice($SecretUpdateTitle, $SecretUpdateQuestion, $SecretUpdateChoices, 1)
    if ($SecretUpdateDecision -eq 0) {
        Write-Output 'The secret value will be updated.'
    } else {
        Write-Output 'The secret value will not be updated.'
        Return $false
    }
} else {
    $SecretExists = $false
}

$SecretString = ConvertTo-Json $SecretStringObject

if ($SecretExists) {
    $SecretUpdate = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager update-secret --secret-id "$($SecretName)" --description "$($Description)" --secret-string "$($SecretString)" | ConvertFrom-Json
    aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager tag-resource --secret-id "$($SecretName)" --tags Key="AssetType",Value="$($Type)" Key="SecretType",Value="$($SecretType)" Key="ARN",Value="$($ARN)" Key="Environment",Value="$($Environment)"
    Return $SecretUpdate.Name
} else {
    $SecretCreation = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager create-secret --name "$($SecretName)" --client-request-token "$([guid]::NewGuid())" --description "$($Description)" --secret-string "$($SecretString)" --tags Key="AssetType",Value="$($Type)" Key="SecretType",Value="$($SecretType)" Key="ARN",Value="$($ARN)" Key="Environment",Value="$($Environment)" | ConvertFrom-Json
    Return $SecretCreation.Name
}
