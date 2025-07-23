#!/bin/bash
# 기존 리소스 Import 명령어들

echo "=== 기존 리소스 Import 시작 ==="

# EKS 관련 IAM 역할
terraform import module.eks.aws_iam_role.cluster "my-eks-cluster-eks-cluster-role"
terraform import module.eks.aws_iam_role.node_group "my-eks-cluster-eks-node-group-role"

# CloudWatch Log Groups
terraform import module.eks.aws_cloudwatch_log_group.eks "/aws/eks/my-eks-cluster/cluster"

# KMS 키 별칭들 (있다면)
terraform import module.eks.aws_kms_alias.eks "alias/my-eks-cluster-eks"

echo "=== Import 완료 ==="