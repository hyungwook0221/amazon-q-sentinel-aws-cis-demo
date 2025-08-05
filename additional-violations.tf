# 추가 보안 정책 위반 사례들
# 더 구체적인 Sentinel 정책 위반을 위한 추가 리소스들

# 1. 개별 보안 그룹 규칙으로 SSH 포트 개방
resource "aws_security_group_rule" "allow_ssh_from_anywhere" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]  # SSH 포트 전 세계 개방 - 정책 위반
  security_group_id = aws_security_group.completely_open.id
  description       = "Allow SSH from anywhere - DANGEROUS!"
}

# 2. VPC 보안 그룹 인그레스 규칙으로 RDP 포트 개방
resource "aws_vpc_security_group_ingress_rule" "allow_rdp_from_anywhere" {
  security_group_id = aws_security_group.completely_open.id
  
  cidr_ipv4   = "0.0.0.0/0"  # RDP 포트 전 세계 개방 - 정책 위반
  from_port   = 3389
  to_port     = 3389
  ip_protocol = "tcp"
  
  description = "Allow RDP from anywhere - DANGEROUS!"
}

# 3. IPv6에서 SSH 포트 개방
resource "aws_vpc_security_group_ingress_rule" "allow_ssh_ipv6" {
  security_group_id = aws_security_group.completely_open.id
  
  cidr_ipv6   = "::/0"  # IPv6에서 SSH 포트 전 세계 개방 - 정책 위반
  from_port   = 22
  to_port     = 22
  ip_protocol = "tcp"
  
  description = "Allow SSH from anywhere via IPv6 - DANGEROUS!"
}

# 4. 모든 프로토콜 허용하는 규칙
resource "aws_security_group_rule" "allow_all_protocols" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"  # 모든 프로토콜 허용 - 정책 위반
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.completely_open.id
  description       = "Allow all protocols from anywhere - EXTREMELY DANGEROUS!"
}

# 5. 계정 레벨 S3 퍼블릭 액세스 차단 비활성화
resource "aws_s3_account_public_access_block" "account_level_block" {
  block_public_acls       = false  # 계정 레벨 퍼블릭 ACL 허용 - 정책 위반
  block_public_policy     = false  # 계정 레벨 퍼블릭 정책 허용 - 정책 위반
  ignore_public_acls      = false  # 계정 레벨 퍼블릭 ACL 무시하지 않음 - 정책 위반
  restrict_public_buckets = false  # 계정 레벨 퍼블릭 버킷 제한하지 않음 - 정책 위반
}

# 6. MFA Delete가 비활성화된 S3 버킷 버전 관리
resource "aws_s3_bucket_versioning" "vulnerable_versioning" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  versioning_configuration {
    status = "Enabled"
    # mfa_delete는 CLI를 통해서만 설정 가능하므로 기본적으로 비활성화됨 - 정책 위반
  }
}

# 7. S3 버킷 로깅 비활성화 (읽기/쓰기 이벤트 로깅 없음)
# CloudTrail에서 S3 데이터 이벤트 로깅이 설정되지 않음 - 정책 위반

# 8. 추가 IAM 정책 문서 (관리자 권한 포함)
data "aws_iam_policy_document" "admin_policy_doc" {
  statement {
    effect = "Allow"
    actions = ["*"]      # 모든 액션 허용 - 정책 위반
    resources = ["*"]    # 모든 리소스에 대해 - 정책 위반
  }
}

resource "aws_iam_policy" "admin_policy_from_doc" {
  name   = "AdminPolicyFromDoc"
  policy = data.aws_iam_policy_document.admin_policy_doc.json
}

# 9. 그룹에 관리자 정책 연결 후 사용자를 그룹에 추가
resource "aws_iam_group" "admin_group" {
  name = "admin-group"
}

resource "aws_iam_group_policy_attachment" "admin_group_policy" {
  group      = aws_iam_group.admin_group.name
  policy_arn = aws_iam_policy.admin_policy_from_doc.arn
}

resource "aws_iam_group_membership" "admin_group_membership" {
  name = "admin-group-membership"
  
  users = [
    aws_iam_user.vulnerable_user.name,
  ]
  
  group = aws_iam_group.admin_group.name
}

# 10. 역할에 관리자 정책 연결
resource "aws_iam_role" "admin_role" {
  name = "admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_role_policy" {
  role       = aws_iam_role.admin_role.name
  policy_arn = aws_iam_policy.admin_policy_from_doc.arn
}

# 11. 네트워크 ACL 설정 (모든 트래픽 허용)
resource "aws_network_acl" "vulnerable_nacl" {
  vpc_id = aws_vpc.vulnerable_vpc.id

  # 모든 인바운드 트래픽 허용 - 정책 위반 가능성
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # 모든 아웃바운드 트래픽 허용
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "vulnerable-nacl"
  }
}

# 12. RDS 인스턴스 (마이너 버전 자동 업그레이드 비활성화)
resource "aws_db_instance" "vulnerable_db_2" {
  identifier = "vulnerable-database-2"
  
  engine         = "postgres"
  engine_version = "13.7"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = false  # 스토리지 암호화 비활성화 - 정책 위반
  
  db_name  = "vulnerabledb2"
  username = "admin"
  password = "password123"
  
  publicly_accessible    = true   # 퍼블릭 액세스 허용 - 정책 위반
  auto_minor_version_upgrade = false  # 마이너 버전 자동 업그레이드 비활성화 - 정책 위반
  skip_final_snapshot    = true
  
  vpc_security_group_ids = [aws_security_group.completely_open.id]
  db_subnet_group_name   = aws_db_subnet_group.vulnerable_subnet_group.name

  tags = {
    Name = "vulnerable-database-2"
  }
}

# 13. 추가 암호화되지 않은 EBS 볼륨들
resource "aws_ebs_volume" "unencrypted_volume_2" {
  availability_zone = "us-west-2a"
  size              = 10
  type              = "gp3"
  encrypted         = false  # 암호화 비활성화 - 정책 위반

  tags = {
    Name = "unencrypted-volume-2"
  }
}

resource "aws_ebs_volume" "unencrypted_volume_3" {
  availability_zone = "us-west-2b"
  size              = 15
  type              = "gp2"
  encrypted         = false  # 암호화 비활성화 - 정책 위반

  tags = {
    Name = "unencrypted-volume-3"
  }
}

# 14. 추가 KMS 키 (로테이션 비활성화)
resource "aws_kms_key" "vulnerable_key_2" {
  description             = "또 다른 취약한 KMS 키"
  deletion_window_in_days = 10
  enable_key_rotation     = false  # 키 로테이션 비활성화 - 정책 위반
  is_enabled              = true

  tags = {
    Name = "vulnerable-key-2"
  }
}

resource "aws_kms_key" "vulnerable_key_3" {
  description             = "세 번째 취약한 KMS 키"
  deletion_window_in_days = 7
  enable_key_rotation     = false  # 키 로테이션 비활성화 - 정책 위반
  is_enabled              = true

  tags = {
    Name = "vulnerable-key-3"
  }
}

# 15. 추가 취약한 S3 버킷
resource "aws_s3_bucket" "vulnerable_bucket_2" {
  bucket = "another-vulnerable-bucket-${random_string.bucket_suffix_2.result}"

  tags = {
    Name = "vulnerable-bucket-2"
  }
}

resource "random_string" "bucket_suffix_2" {
  length  = 8
  special = false
  upper   = false
}

# SSL을 요구하지 않는 또 다른 버킷 정책
resource "aws_s3_bucket_policy" "vulnerable_bucket_policy_2" {
  bucket = aws_s3_bucket.vulnerable_bucket_2.id

  # 인라인 정책 사용 - 정책 위반
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicReadWrite"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = "${aws_s3_bucket.vulnerable_bucket_2.arn}/*"
      }
    ]
  })
}

# 16. 추가 취약한 EC2 인스턴스
resource "aws_instance" "vulnerable_instance_2" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.small"
  subnet_id     = aws_subnet.vulnerable_subnet_2.id
  
  vpc_security_group_ids = [aws_security_group.completely_open.id]

  # IMDSv2를 강제하지 않음 - 정책 위반
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # required로 설정해야 함
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp2"
    volume_size = 30
    encrypted   = false  # 루트 볼륨 암호화 비활성화 - 정책 위반
  }

  tags = {
    Name = "vulnerable-instance-2"
  }
}

# 출력
output "additional_warnings" {
  value = <<-EOT
    🚨 추가 보안 위반 사항들:
    
    - 개별 보안 그룹 규칙으로 SSH/RDP 포트 전 세계 개방
    - IPv6에서도 위험한 포트 개방
    - 모든 프로토콜 허용하는 규칙
    - 계정 레벨 S3 퍼블릭 액세스 차단 비활성화
    - MFA Delete 비활성화
    - S3 데이터 이벤트 로깅 없음
    - 여러 IAM 엔티티에 관리자 권한 부여
    - 네트워크 ACL에서 모든 트래픽 허용
    - RDS 마이너 버전 자동 업그레이드 비활성화
    - 다수의 암호화되지 않은 EBS 볼륨
    - 다수의 키 로테이션 비활성화된 KMS 키
    - 추가 SSL 요구사항 없는 S3 버킷
    - 추가 IMDSv2 미적용 EC2 인스턴스
    
    이 모든 설정들이 Sentinel 정책에 의해 감지되어야 합니다!
  EOT
}