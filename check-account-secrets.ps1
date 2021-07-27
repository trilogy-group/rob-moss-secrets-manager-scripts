#Requires -Version 7.1.3
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

Write-Output "List of ARNs missing secrets in Secrets Manager in account $($AccountID) with profile name $($ProfileName):"
Write-Output "`n"

(aws ec2 describe-regions | ConvertFrom-Json).Regions.RegionName | ForEach-Object -Parallel {
    $EC2Instances = aws --region $_ --profile "$($using:ProfileName)" ec2 describe-instances | ConvertFrom-Json
    $EC2KeyPairARNs = @()
    $EC2InstanceARNs = @()
    $EC2ASGARNs = @()
    $RDSDatabaseClusterARNs = @()
    $RDSDatabaseInstanceARNs = @()
    $AllARNs = @()
    $AutoScalingInstances = (aws --region $_ --profile "$($using:ProfileName)" autoscaling describe-auto-scaling-instances | ConvertFrom-Json).AutoScalingInstances.InstanceId
    if (-Not($AutoScalingInstances)) {
        $AutoScalingInstances = @()
    }
    foreach ($Reservation in $EC2Instances.Reservations) {
        foreach ($Instance in $Reservation.Instances) {
            if (-Not($AutoScalingInstances.Contains($Instance.InstanceId))) {
                $ARN = "arn:aws:ec2:$($_):$($using:AccountID):instance/$($Instance.InstanceId)"
                if ($Instance.InstanceId) {
                    if (-Not($EC2InstanceARNs.Contains($ARN))) {
                        $EC2InstanceARNs += $ARN
                    }
                }
                if ($Instance.KeyName) {
                    if (-Not($EC2KeyPairARNs.Contains("arn:aws:ec2:$($_):$($using:AccountID):key-pair/$($Instance.KeyName)"))) {
                        $EC2KeyPairARNs += "arn:aws:ec2:$($_):$($using:AccountID):key-pair/$($Instance.KeyName)" -replace '[^a-zA-Z0-9 :_@\/\+\=\.\-]', ''
                    }
                }
            }
        }
    }
    $EC2ASGs = aws --region $_ --profile "$($using:ProfileName)" autoscaling describe-auto-scaling-groups | ConvertFrom-Json
    foreach ($EC2ASG in $EC2ASGs.AutoScalingGroups) {
        if ($EC2ASG.AutoScalingGroupARN) {
            if (-Not($EC2ASGARNs.Contains($EC2ASG.AutoScalingGroupARN))) {
                $EC2ASGARNs += $EC2ASG.AutoScalingGroupARN -replace '[^a-zA-Z0-9 :_@\/\+\=\.\-]', ''
            }
        }
    }
    $RDSDatabaseClusters = aws --region $_ --profile "$($using:ProfileName)" rds describe-db-clusters | ConvertFrom-Json
    foreach ($RDSDatabaseCluster in $RDSDatabaseClusters.DBClusters) {
        if ($RDSDatabaseCluster.DBClusterARN) {
            if (-Not($RDSDatabaseClusterARNs.Contains($RDSDatabaseCluster.DBClusterARN))) {
                $RDSDatabaseClusterARNs += $RDSDatabaseCluster.DBClusterARN
            }
        }
    }
    $RDSDatabaseInstances = aws --region $_ --profile "$($using:ProfileName)" rds describe-db-instances | ConvertFrom-Json
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
    $GroupSize = 9
    $Iterator = 0
    do {
        $AllARNsSubGroup = $AllARNs[$Iterator..(($Iterator += $GroupSize) -1)]
        $ARNSearch = ($AllARNsSubGroup -join ",")
        $SecretARNs = @()
        $SecretList = aws --region $_ --profile "$($using:ProfileName)" secretsmanager list-secrets --filters "Key=tag-key,Values=ARN" "Key=tag-value,Values=$($ARNSearch)" | ConvertFrom-Json
        foreach ($Secret in $SecretList.SecretList) {
            foreach ($Tag in $Secret.Tags) {
                if ($Tag.Key -eq "ARN") {
                    $SecretARNs += $Tag.Value
                }
            }
        }
        if (-Not($AllARNsSubGroup.Length -eq 0)) {
            foreach ($ARN in $AllARNsSubGroup) {
                if (-Not($SecretARNs.Contains($ARN))) {
                    Write-Warning "Secret missing for $($ARN)"
                } else {
                    Write-Output "Secret already created for $($ARN)"
                }
            }
        }
    } until ($Iterator -ge $AllARNs.Count)
}  -ThrottleLimit 100

Write-Output "`n"
