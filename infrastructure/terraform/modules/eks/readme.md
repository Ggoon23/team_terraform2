# EKS 클러스터가 생성될 때 AWS가 자동으로 aws-auth ConfigMap을 생성하는데, Terraform 코드에서도 이를 생성하려고 해서 충돌이 발생

terraform import module.eks.kubernetes_config_map_v1.aws_auth kube-system/aws-auth

import 명령어 실행으로 기존 리소스를 Terraform 상태에 추가