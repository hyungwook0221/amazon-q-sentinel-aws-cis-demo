# 취약한 AWS 인프라 샘플 코드
# 이 코드는 의도적으로 여러 보안 정책을 위반하여 Sentinel 정책 테스트를 위한 것입니다.
# 실제 프로덕션 환경에서는 절대 사용하지 마세요!

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# 1. VPC 및 네트워킹 설정 (Flow Logging 비활성화)
resource "aws_vpc" "vulnerable_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "vulnerable-vpc"
  }
  # VPC Flow Logging이 활성화되지 않음 - 정책 위반
}

resource "aws_subnet" "vulnerable_subnet" {
  vpc_id                  = aws_vpc.vulnerable_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "vulnerable-subnet"
  }
}

resource "aws_internet_gateway" "vulnerable_igw" {
  vpc_id = aws_vpc.vulnerable_vpc.id

  tags = {
    Name = "vulnerable-igw"
  }
}

# 2. 극도로 취약한 보안 그룹 (모든 포트 개방)
resource "aws_security_group" "completely_open" {
  name        = "completely-open-sg"
  description = "완전히 개방된 보안 그룹 - 매우 위험!"
  vpc_id      = aws_vpc.vulnerable_vpc.id

  # SSH 포트 22번을 전 세계에 개방 - 정책 위반
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # RDP 포트 3389번을 전 세계에 개방 - 정책 위반
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # 모든 포트를 전 세계에 개방 - 정책 위반
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # IPv6에서도 모든 포트 개방 - 정책 위반
  ingress {
    from_port        = 0
    to_port          = 65535
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "completely-open-sg"
  }
}

# 3. 기본 보안 그룹에 트래픽 허용 - 정책 위반
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.vulnerable_vpc.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 4. 암호화되지 않은 EBS 볼륨 - 정책 위반
resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-west-2a"
  size              = 20
  encrypted         = false  # 암호화 비활성화 - 정책 위반

  tags = {
    Name = "unencrypted-volume"
  }
}

# 5. 취약한 EC2 인스턴스 (IMDSv1 허용, 암호화되지 않은 스토리지)
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c02fb55956c7d316"  # Amazon Linux 2
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.vulnerable_subnet.id
  
  vpc_security_group_ids = [aws_security_group.completely_open.id]

  # IMDSv2를 강제하지 않음 - 정책 위반
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # required로 설정해야 함
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = false  # 루트 볼륨 암호화 비활성화 - 정책 위반
  }

  tags = {
    Name = "vulnerable-instance"
  }
}

# 6. KMS 키 (키 로테이션 비활성화) - 정책 위반
resource "aws_kms_key" "vulnerable_key" {
  description             = "취약한 KMS 키"
  deletion_window_in_days = 7
  enable_key_rotation     = false  # 키 로테이션 비활성화 - 정책 위반

  tags = {
    Name = "vulnerable-key"
  }
}

# 7. 암호화되지 않은 RDS 인스턴스 - 정책 위반
resource "aws_db_instance" "vulnerable_db" {
  identifier = "vulnerable-database"
  
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = false  # 스토리지 암호화 비활성화 - 정책 위반
  
  db_name  = "vulnerabledb"
  username = "admin"
  password = "password123"  # 약한 패스워드
  
  publicly_accessible = true   # 퍼블릭 액세스 허용 - 정책 위반
  skip_final_snapshot = true
  
  vpc_security_group_ids = [aws_security_group.completely_open.id]
  db_subnet_group_name   = aws_db_subnet_group.vulnerable_subnet_group.name

  tags = {
    Name = "vulnerable-database"
  }
}

resource "aws_db_subnet_group" "vulnerable_subnet_group" {
  name       = "vulnerable-subnet-group"
  subnet_ids = [aws_subnet.vulnerable_subnet.id, aws_subnet.vulnerable_subnet_2.id]

  tags = {
    Name = "vulnerable-subnet-group"
  }
}

resource "aws_subnet" "vulnerable_subnet_2" {
  vpc_id            = aws_vpc.vulnerable_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "vulnerable-subnet-2"
  }
}

# 8. 퍼블릭 액세스가 허용된 S3 버킷 (SSL 요구사항 없음)
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-extremely-vulnerable-bucket-${random_string.bucket_suffix.result}"

  tags = {
    Name = "vulnerable-bucket"
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 버킷 퍼블릭 액세스 차단 비활성화 - 정책 위반
resource "aws_s3_bucket_public_access_block" "vulnerable_bucket_pab" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false  # 퍼블릭 ACL 허용 - 정책 위반
  block_public_policy     = false  # 퍼블릭 정책 허용 - 정책 위반
  ignore_public_acls      = false  # 퍼블릭 ACL 무시하지 않음 - 정책 위반
  restrict_public_buckets = false  # 퍼블릭 버킷 제한하지 않음 - 정책 위반
}

# SSL을 요구하지 않는 버킷 정책 - 정책 위반
resource "aws_s3_bucket_policy" "vulnerable_bucket_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  # 인라인 정책 사용 (data source 사용하지 않음) - 정책 위반
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      }
    ]
  })
}

# 9. 관리자 권한을 가진 IAM 정책 - 정책 위반
resource "aws_iam_policy" "admin_policy" {
  name        = "AdminPolicy"
  description = "관리자 권한을 가진 정책"

  # 인라인 정책 사용 (data source 사용하지 않음) - 정책 위반
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"        # 모든 액션 허용 - 정책 위반
        Resource = "*"        # 모든 리소스에 대해 - 정책 위반
      }
    ]
  })
}

# 10. 사용자에게 직접 정책 연결 - 정책 위반
resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-user"

  tags = {
    Name = "vulnerable-user"
  }
}

resource "aws_iam_user_policy_attachment" "vulnerable_user_policy" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

# 11. 약한 패스워드 정책
resource "aws_iam_account_password_policy" "weak_password_policy" {
  minimum_password_length        = 6     # 너무 짧음 - 정책 위반
  require_lowercase_characters   = false # 소문자 요구하지 않음 - 정책 위반
  require_numbers               = false # 숫자 요구하지 않음 - 정책 위반
  require_uppercase_characters   = false # 대문자 요구하지 않음 - 정책 위반
  require_symbols               = false # 특수문자 요구하지 않음 - 정책 위반
  allow_users_to_change_password = true
  max_password_age              = 0     # 패스워드 만료 없음 - 정책 위반
  password_reuse_prevention     = 0     # 패스워드 재사용 방지 없음 - 정책 위반
}

# 12. CloudTrail 설정 (로깅 및 암호화 비활성화)
resource "aws_cloudtrail" "vulnerable_trail" {
  name           = "vulnerable-trail"
  s3_bucket_name = aws_s3_bucket.vulnerable_bucket.bucket

  # 로그 파일 검증 비활성화 - 정책 위반
  enable_log_file_validation = false

  # CloudWatch Logs 그룹 설정하지 않음 - 정책 위반
  # cloud_watch_logs_group_arn = null

  # 서버 사이드 암호화 비활성화 - 정책 위반
  # kms_key_id = null

  tags = {
    Name = "vulnerable-trail"
  }
}

# 13. EFS 파일 시스템 (암호화 비활성화) - 정책 위반
resource "aws_efs_file_system" "vulnerable_efs" {
  creation_token = "vulnerable-efs"
  encrypted      = false  # 암호화 비활성화 - 정책 위반

  tags = {
    Name = "vulnerable-efs"
  }
}

# 출력
output "warnings" {
  value = <<-EOT
    ⚠️  경고: 이 인프라는 의도적으로 취약하게 설계되었습니다!
    
    다음과 같은 보안 위반 사항들이 포함되어 있습니다:
    - SSH(22), RDP(3389) 포트가 전 세계에 개방
    - 모든 트래픽이 0.0.0.0/0에서 허용됨
    - EBS, RDS, EFS 암호화 비활성화
    - KMS 키 로테이션 비활성화
    - S3 버킷 퍼블릭 액세스 허용
    - SSL 요구사항 없음
    - IAM 관리자 권한 남용
    - 약한 패스워드 정책
    - CloudTrail 보안 기능 비활성화
    - VPC Flow Logging 비활성화
    - EC2 IMDSv2 미적용
    
    실제 환경에서는 절대 사용하지 마세요!
  EOT
}