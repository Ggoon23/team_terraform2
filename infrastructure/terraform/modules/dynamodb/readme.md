# 🏗️ Infrastructure Modules

**Terraform 기반 AWS 인프라 보안 자동화 및 Splunk 통합 보안 모니터링 플랫폼**

## 📋 모듈 구성

| 모듈 | 목적 | 핵심 기능 | ISMS-P |
|------|------|-----------|---------|
| **🌐 VPC** | 네트워크 격리 | Multi-AZ, Flow Logs, 3-Tier | ✅ |
| **🗃️ RDS** | 관계형 DB | 암호화, Multi-AZ, 백업 | ✅ |
| **☸️ EKS** | 컨테이너 오케스트레이션 | 시크릿 암호화, RBAC, 로깅 | ✅ |
| **🗂️ S3** | 객체 스토리지 | KMS 암호화, 라이프사이클, 로깅 | ✅ |
| **🗄️ DynamoDB** | NoSQL DB | PITR, 스트림, Auto Scaling | ✅ |

## 🚀 빠른 시작

```bash
# 1. 변수 설정
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# 2. 초기화 및 배포
terraform init
terraform plan
terraform apply
```

## 🔒 보안 특징

### **암호화 (Encryption at Rest/Transit)**
- 모든 데이터 KMS 암호화
- TLS 1.2+ 강제 적용
- 시크릿 자동 로테이션

### **접근 제어 (IAM & RBAC)**
- 최소 권한 원칙
- MFA 강제 적용
- 세션 토큰 기반 인증

### **모니터링 (Comprehensive Logging)**
- CloudTrail: API 호출 기록
- VPC Flow Logs: 네트워크 트래픽
- GuardDuty: 위협 탐지
- Config: 설정 변경 추적

## 📊 ISMS-P 컴플라이언스

| 항목 | 요구사항 | 구현 |
|------|----------|------|
| **2.7.1** | 암호정책 적용 | KMS, TLS 1.2+ |
| **2.9.4** | 로그 관리 | 365일+ 보관 |
| **2.5.1** | 계정 관리 | IAM, RBAC |
| **2.6.1** | 네트워크 접근 | Security Groups, NACLs |

## 🏗️ 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                        VPC                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Public    │  │   Private   │  │  Database   │     │
│  │   Subnet    │  │   Subnet    │  │   Subnet    │     │
│  │             │  │             │  │             │     │
│  │    ALB      │  │    EKS      │  │    RDS      │     │
│  │             │  │  Workers    │  │ DynamoDB    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
                            │
                    ┌─────────────┐
                    │      S3     │
                    │    Logs     │
                    └─────────────┘
                            │
                    ┌─────────────┐
                    │    Splunk   │
                    │  Universal  │
                    │  Forwarder  │
                    └─────────────┘
```

## 📁 파일 구조

```
infrastructure/terraform/
├── modules/
│   ├── vpc/         # 네트워크 기반
│   ├── rds/         # 관계형 데이터베이스
│   ├── eks/         # Kubernetes 클러스터
│   ├── s3/          # 객체 스토리지
│   └── dynamodb/    # NoSQL 데이터베이스
└── environments/
    ├── dev/         # 개발 환경
    ├── staging/     # 스테이징 환경
    └── prod/        # 운영 환경
```

## ⚙️ 변수 예시

```hcl
# terraform.tfvars
project_name = "security-monitoring"
environment  = "prod"

# VPC 설정
vpc_cidr = "10.0.0.0/16"
availability_zones = ["ap-northeast-2a", "ap-northeast-2c"]

# 보안 설정
enable_deletion_protection = true
log_retention_days = 365
create_kms_keys = true

# 태그
common_tags = {
  Project     = "Security-Monitoring"
  Environment = "Production"
  Team        = "Team2"
  Owner       = "Infrastructure"
}
```

## 🔍 주요 출력값

```bash
# VPC 정보
terraform output vpc_id
terraform output private_subnet_ids

# 데이터베이스 연결 정보  
terraform output rds_endpoint
terraform output dynamodb_table_name

# 보안 정보
terraform output kms_key_arns
terraform output s3_log_bucket
```

## 📈 모니터링 대시보드

### **CloudWatch 메트릭**
- EC2/EKS: CPU, 메모리, 네트워크
- RDS: 연결, 쿼리 성능, 복제 지연
- DynamoDB: 읽기/쓰기 용량, 스로틀링

### **Splunk 연동**
- 실시간 로그 수집
- 보안 이벤트 상관분석  
- ISMS-P 컴플라이언스 리포트

## 🛠️ 운영 가이드

### **백업 정책**
- RDS: 7일 자동 백업
- DynamoDB: PITR 35일
- S3: 버전 관리 + 라이프사이클

### **재해 복구**
- Multi-AZ 배포
- Cross-Region 복제
- 자동 장애 조치

### **비용 최적화**
- Reserved Instances
- Spot Instances (개발환경)
- S3 Intelligent Tiering
- DynamoDB On-Demand

## 🚨 주의사항

⚠️ **운영 환경 배포 전 필수 확인**
- [ ] KMS 키 백업
- [ ] IAM 권한 검토
- [ ] 네트워크 ACL 확인
- [ ] 백업 정책 테스트

## 🤝 기여 가이드

1. Feature 브랜치 생성
2. Terraform validate/plan 실행
3. 보안 스캔 (checkov, tfsec)
4. Pull Request 생성

---
**📧 Contact**: Team2 Infrastructure  
**🔗 Documentation**: [Confluence Link]  
**🎯 JIRA**: [Project Board]