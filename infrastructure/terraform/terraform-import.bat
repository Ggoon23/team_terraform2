@echo off
echo === Terraform 기존 리소스 Import 시작 ===

echo CloudWatch Log Groups 임포트...
terraform import aws_cloudwatch_log_group.application_logs "/aws/application/dev-app-dev"
terraform import aws_cloudwatch_log_group.security_logs "/aws/security/dev-app-dev"

echo KMS Aliases 임포트...
terraform import aws_kms_alias.main "alias/dev-app-dev"

echo DynamoDB Tables 임포트...
terraform import module.dynamodb_security_logs.aws_dynamodb_table.main "security-logs-metadata"
terraform import module.dynamodb_user_sessions.aws_dynamodb_table.main "user-sessions"

echo EKS 리소스 임포트...
terraform import module.eks.aws_kms_alias.eks "alias/dev-app-dev-eks-eks"
terraform import module.eks.aws_cloudwatch_log_group.eks "/aws/eks/dev-app-dev-eks/cluster"
terraform import module.eks.aws_iam_role.cluster "dev-app-dev-eks-eks-cluster-role"
terraform import module.eks.aws_iam_role.node_group "dev-app-dev-eks-eks-node-group-role"

echo Lambda 리소스 임포트...
terraform import module.lambda_log_processor.aws_iam_role.lambda "log-processor-execution-role"
terraform import module.lambda_security_alert.aws_iam_role.lambda "security-alert-execution-role"
terraform import module.lambda_log_processor.aws_cloudwatch_log_group.lambda "/aws/lambda/log-processor"
terraform import module.lambda_security_alert.aws_cloudwatch_log_group.lambda "/aws/lambda/security-alert"

echo RDS 리소스 임포트...
terraform import module.rds.aws_db_subnet_group.main "dev-app-db-subnet-group"
terraform import module.rds.aws_db_parameter_group.main "dev-app-db-parameter-group"
terraform import module.rds.aws_kms_alias.rds[0] "alias/dev-app-rds"
terraform import "module.rds.aws_cloudwatch_log_group.rds[\"postgresql\"]" "/aws/rds/instance/my-rds-database/postgresql"
terraform import module.rds.aws_iam_role.rds_monitoring[0] "dev-app-rds-monitoring-role"

echo S3 리소스 임포트...
terraform import module.s3.aws_kms_alias.s3[0] "alias/dev-app-s3"

echo Security Log Collectors 리소스 임포트...
terraform import module.security_log_collectors.aws_cloudwatch_log_group.cloudtrail[0] "/aws/cloudtrail/dev-app"
terraform import module.security_log_collectors.aws_iam_role.cloudtrail_cloudwatch[0] "dev-app-cloudtrail-cloudwatch-role"
terraform import module.security_log_collectors.aws_iam_role.splunk_forwarder "dev-app-splunk-forwarder-role"
terraform import module.security_log_collectors.aws_iam_role.config[0] "dev-app-config-role"
terraform import module.security_log_collectors.aws_iam_role.flow_log[0] "dev-app-vpc-flow-log-role"

echo VPC 리소스 임포트...
terraform import module.vpc.aws_cloudwatch_log_group.vpc_flow_log[0] "/aws/vpc/flowlogs/dev-app"
terraform import module.vpc.aws_iam_role.flow_log[0] "dev-app-vpc-flow-log-role"

echo SSM Parameter 임포트...
terraform import aws_ssm_parameter.security_policy "/dev-app/dev/security/policy"

echo === Import 완료 ===
echo GuardDuty와 Security Hub는 수동으로 import하세요
pause