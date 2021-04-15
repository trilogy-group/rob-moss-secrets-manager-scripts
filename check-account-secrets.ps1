<#
  .SYNOPSIS
  Checks that all EC2 Instances, EC2 Auto-Scaling Groups, EC2 Key Pairs, RDS database clusters, and RDS database instances in an AWS account have secrets in Secrets Manager. You must supply an AccountID and a ProfileName that match.

  .DESCRIPTION
  This script finds all the enabled regions in the provided AWS account, lists all the relevant resources, and searches for a secret in Secrets Manager for each one. Note that the secret values themselves are not checked to see if the logins are valid, as that would require network access which cannot be guaranteed.

  RDS database instances that are members of RDS database clusters, and EC2 Instances that are members of EC2 Auto-Scaling Groups, are not individually listed.

  .PARAMETER AccountID Perform a lookup to ensure that the configured account matches the account for which credentials are to be created.

  .PARAMETER ProfileName Use this profile for AWS CLI calls.

  .INPUTS
  None. You cannot pipe objects to this script.

  .OUTPUTS
  System.String. This script outputs a list of resources which are missing secrets in Secrets Manager.

  .EXAMPLE
  PS> .\check-account-secrets.ps1 -AccountID 012345678901 -ProfileName "default"
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern("[0-9]{12}")]
    [String]
    $AccountID,
    [Parameter(Mandatory = $false)]
    [String]
    $ProfileName = "default"
)

$Response = aws --profile "$($ProfileName)" sts get-caller-identity | ConvertFrom-Json
if (-Not($Response.Account)) {
    Write-Error -Message "Could not role switch into this AWS account."
    Return $false
}
if (-Not($Response.Account -eq $AccountID)) {
    Write-Error -Message "The specified account ID does not match the AWS CLI profile in use."
    Return $false
}

$RegionNames = (aws ec2 describe-regions | ConvertFrom-Json).Regions.RegionName | Sort-Object

Write-Output "List of ARNs missing secrets in Secrets Manager in account $($AccountID) with profile name $($ProfileName):"
Write-Output "`n"

# ARNs must match pattern: ^\!?[a-zA-Z0-9 :_@\/\+\=\.\-]*$]
foreach ($Region in $RegionNames) {
    $EC2Instances = aws --region "$($Region)" --profile "$($ProfileName)" ec2 describe-instances | ConvertFrom-Json
    $EC2KeyPairARNs = @()
    $EC2InstanceARNs = @()
    $EC2ASGARNs = @()
    $RDSDatabaseClusterARNs = @()
    $RDSDatabaseInstanceARNs = @()
    $AllARNs = @()
    foreach ($Reservation in $EC2Instances.Reservations) {
        if (-Not($Reservation.RequesterID -eq "940372691376")) {
            foreach ($Instance in $Reservation.Instances) {
                $ARN = "arn:aws:ec2:$($Region):$($AccountID):instance/$($Instance.InstanceId)"
                if ($Instance.InstanceId) {
                    if (-Not($EC2InstanceARNs.Contains($ARN))) {
                        $EC2InstanceARNs += $ARN
                    }
                }
                if ($Instance.KeyName) {
                    if (-Not($EC2KeyPairARNs.Contains("arn:aws:ec2:$($Region):$($AccountID):key-pair/$($Instance.KeyName)"))) {
                        $EC2KeyPairARNs += "arn:aws:ec2:$($Region):$($AccountID):key-pair/$($Instance.KeyName)" -replace '[^a-zA-Z0-9 :_@\/\+\=\.\-]', ''
                    }
                }
            }
        }
    }
    $EC2ASGs = aws --region "$($Region)" --profile "$($ProfileName)" autoscaling describe-auto-scaling-groups | ConvertFrom-Json
    foreach ($EC2ASG in $EC2ASGs.AutoScalingGroups) {
        if ($EC2ASG.AutoScalingGroupARN) {
            if (-Not($EC2ASGARNs.Contains($EC2ASG.AutoScalingGroupARN))) {
                $EC2ASGARNs += $EC2ASG.AutoScalingGroupARN -replace '[^a-zA-Z0-9 :_@\/\+\=\.\-]', ''
            }
        }
    }
    $RDSDatabaseClusters = $Response = aws --region "$($Region)" --profile "$($ProfileName)" rds describe-db-clusters | ConvertFrom-Json
    foreach ($RDSDatabaseCluster in $RDSDatabaseClusters.DBClusters) {
        if ($RDSDatabaseCluster.DBClusterARN) {
            if (-Not($RDSDatabaseClusterARNs.Contains($RDSDatabaseCluster.DBClusterARN))) {
                $RDSDatabaseClusterARNs += $RDSDatabaseCluster.DBClusterARN
            }
        }
    }
    $RDSDatabaseInstances = $Response = aws --region "$($Region)" --profile "$($ProfileName)" rds describe-db-instances | ConvertFrom-Json
    foreach ($RDSDatabaseInstance in $RDSDatabaseInstances.DBInstances) {
        if (-Not($RDSDatabaseInstance.DBClusterIdentifier)) {
            if ($RDSDatabaseInstance.DBInstanceArn) {
                if (-Not($RDSDatabaseInstanceARNs.Contains($RDSDatabaseInstance.DBInstanceArn))) {
                    $RDSDatabaseInstanceARNs += $RDSDatabaseInstance.DBInstanceArn
                }
            }
        }
    }
    $AllARNs += $EC2KeyPairARNs
    $AllARNs += $EC2InstanceARNs
    $AllARNs += $EC2ASGARNs
    $AllARNs += $RDSDatabaseClusterARNs
    $AllARNs += $RDSDatabaseInstanceARNs
    $SecretARNs = @()
    $ARNSearch = ($AllARNs -join ",")
    $SecretList = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager list-secrets --filters "Key=tag-key,Values=ARN" "Key=tag-value,Values=$($ARNSearch)" | ConvertFrom-Json
    foreach ($Secret in $SecretList) {
        if ($Secret.ARN) {
            $SecretARNs += $Secret.ARN
        }
    }
    if (-Not($AllARNs.Length -eq 0)) {
        foreach ($ARN in $AllARNs) {
            if (-Not($SecretARNs.Contains($ARN))) {
                Write-Output $ARN
            }
        }
    }
}

Write-Output "`n"
