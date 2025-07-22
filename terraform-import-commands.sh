#!/bin/bash
# Terraform import 명령어들

# CloudWatch Log Groups
terraform import aws_cloudwatch_log_group.application_logs "/aws/application/dev-app-dev"
terraform import aws_cloudwatch_log_group.security_logs "/aws/security/dev-app-dev"

# KMS Aliases
terraform import aws_kms_alias.main "alias/dev-app-dev"

# DynamoDB Tables
terraform import module.dynamodb_security_logs.aws_dynamodb_table.main "security-logs-metadata"
terraform import module.dynamodb_user_sessions.aws_dynamodb_table.main "user-sessions"

# IAM Roles
terraform import module.eks.aws_iam_role.cluster "dev-app-dev-eks-eks-cluster-role"
terraform import module.eks.aws_iam_role.node_group "dev-app-dev-eks-eks-node-group-role"
terraform import module.lambda_log_processor.aws_iam_role.lambda "log-processor-execution-role"
terraform import module.lambda_security_alert.aws_iam_role.lambda "security-alert-execution-role"

# RDS 관련
terraform import module.rds.aws_db_subnet_group.main "dev-app-db-subnet-group"
terraform import module.rds.aws_db_parameter_group.main "dev-app-db-parameter-group"

# Security Services
terraform import module.security_log_collectors.aws_guardduty_detector.main[0] "<detector-id>"
terraform import module.security_log_collectors.aws_securityhub_account.main[0] "902597156026"

# SSM Parameter
terraform import aws_ssm_parameter.security_policy "/dev-app/dev/security/policy"