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
if (-Not($Response.Account -eq $AccountID)) {
    Write-Error -Message "The specified account ID does not match the AWS CLI profile in use."
    Return $false
}

$RegionNames = (aws ec2 describe-regions | ConvertFrom-Json).Regions.RegionName | Sort-Object

# arn:aws:ec2:us-east-1:012345678901:instance/i-0123456789abcdef0
# arn:aws:autoscaling:us-east-1:012345678901:autoScalingGroup:01234567-89ab-cdef-0123-456789abcdef:autoScalingGroupName/example-autoscaling-group
# arn:aws:ec2:us-east-1:012345678901:key-pair/example-key-pair
# arn:aws:rds:us-east-1:012345678901:cluster:example-db-cluster
# arn:aws:rds:us-east-1:012345678901:instance:example-db-instance

Write-Output "List of ARNs missing secrets in Secrets Manager:"
Write-Output "`r`n"

foreach ($Region in $RegionNames) {
    $EC2Instances = aws --region "$($Region)" --profile "$($ProfileName)" ec2 describe-instances | ConvertFrom-Json
    foreach ($Reservation in $EC2Instances.Reservations) {
        if (-Not($Reservation.RequesterID -eq "940372691376")) {
            foreach ($Instance in $Reservation.Instances) {
                $ARN = "arn:aws:ec2:$($Region):$($AccountID):instance/$($Instance.InstanceId)"
                $SecretList = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager list-secrets --filters "Key=tag-key,Values=ARN" "Key=tag-value,Values=$($ARN)" | ConvertFrom-Json
                if (-Not($SecretList.SecretList[0].ARN)) {
                    Write-Output $ARN
                }
            }
        }
    }
}
foreach ($Region in $RegionNames) {
    $EC2ASGs = aws --region "$($Region)" --profile "$($ProfileName)" autoscaling describe-auto-scaling-groups | ConvertFrom-Json
    foreach ($EC2ASG in $EC2ASGs.AutoScalingGroups) {
        $SecretList = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager list-secrets --filters "Key=tag-key,Values=ARN" "Key=tag-value,Values=$($EC2ASG.AutoScalingGroupARN)" | ConvertFrom-Json
        if (-Not($SecretList.SecretList[0].ARN)) {
            Write-Output $EC2ASG.AutoScalingGroupARN
        }
    }
}
foreach ($Region in $RegionNames) {
    $EC2KeyPairs = aws --region "$($Region)" --profile "$($ProfileName)" ec2 describe-key-pairs | ConvertFrom-Json
    foreach ($EC2KeyPair in $EC2KeyPairs.KeyPairs) {
        $ARN = "arn:aws:ec2:$($Region):$($AccountID):key-pair/$($EC2KeyPair.KeyName)"
        $SecretList = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager list-secrets --filters "Key=tag-key,Values=ARN" "Key=tag-value,Values=$($ARN)" | ConvertFrom-Json
        if (-Not($SecretList.SecretList[0].ARN)) {
            Write-Output $ARN
        }
    }
}
foreach ($Region in $RegionNames) {
    $RDSDatabaseClusters = $Response = aws --region "$($Region)" --profile "$($ProfileName)" rds describe-db-clusters | ConvertFrom-Json
    foreach ($RDSDatabaseCluster in $RDSDatabaseClusters.DBClusters) {
        $SecretList = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager list-secrets --filters "Key=tag-key,Values=ARN" "Key=tag-value,Values=$($RDSDatabaseCluster.DBClusterArn)" | ConvertFrom-Json
        if (-Not($SecretList.SecretList[0].ARN)) {
            Write-Output $RDSDatabaseCluster.DBClusterArn
        }
    }
}
foreach ($Region in $RegionNames) {
    $RDSDatabaseInstances = $Response = aws --region "$($Region)" --profile "$($ProfileName)" rds describe-db-instances | ConvertFrom-Json
    foreach ($RDSDatabaseInstance in $RDSDatabaseInstances.DBInstances) {
        if (-Not($RDSDatabaseInstance.DBClusterIdentifier)) {
            $SecretList = aws --region "$($Region)" --profile "$($ProfileName)" secretsmanager list-secrets --filters "Key=tag-key,Values=ARN" "Key=tag-value,Values=$($RDSDatabaseInstance.DBInstanceArn)" | ConvertFrom-Json
            if (-Not($SecretList.SecretList[0].ARN)) {
                Write-Output $RDSDatabaseInstance.DBInstanceArn
            }
        }
    }
}
