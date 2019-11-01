data "terraform_remote_state" "vpc" {
  backend = "s3"

  config = {
    bucket = "terraform-remote-state-infosec-engineering-vpc"
    key    = "vpc/terraform.tfstate"
    region = var.vpc_region
  }
}

resource "aws_key_pair" "ja3_ssh" {
  key_name      = "ja3-ssh-key"
  public_key    = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCg7keB8zqXcRqvBJrB6ndGCGa5aorNoTLk5zMGdWuHCIZbgYDPSbuUSFhVuylct4VmrCCbXZ78P5oScA+iNtnkZzGIfx6Bh8V0G2dohZNkPivf7X1DWr2IB6UMvi9MNxDByJlXkbBskWaV7aYpnHj50+p6tQJUhhFrK5mtgmU+EBg2P9P407JcRslKakunSPUcQZGeMwiNyiUIr0R1O9aQ5B3csWWKYvklZwM1Y7ZvjN1WzYrHsTVkCKXOCJMZRpj+1eIJM8FldJ2rWcUGB1PPe0Hwu3j4DW6zUZU6Ruj2ABQyFlGgOCcXz0zkTUJe+gtbVXotagrex10+9LIxGIPyg1yM6TF3O3/8AInyGU1fIocVwaFLXNyKpNMTU7chSx57Fab5crs4y+kuWHeWvR1ON3VWN9VujY1UnH0uRqmaG30sTL2Pj3WOZ3W/+ro7Q3ecG+YfBjaXNy9EStnoHDkyjDk/tsbbMOEr8qAsHvoxNL2zKOIDvEe06bci7zwPDrBHWDUmvTBSXrCtGtYwzIqtZh/qBjW7+UijLpDOF0PZjwMG7B42NDjfC/4QrTzkoY3fTlVHd0i/TrusRNOpXukhRQC4HfF+3pw6fs99q+VpgXtnDAUkjfutya7K+5F2PqeoqUgc9kqvmlWuNamAaLV3qIPc3k63IDcfphR7A2ldxQ== steve.sakol@C02VX8U7HTD5"
}

data "aws_ami" "ubuntu_18_04" {
    most_recent = true

    filter {
        name = "name"
        values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
    }

    filter {
        name   = "virtualization-type"
        values = ["hvm"]
    }

    owners = ["099720109477"] # Canonical
}


resource "aws_instance" "ja3" {
  ami                       = data.aws_ami.ubuntu_18_04.id
  instance_type             = "t2.micro"
  vpc_security_group_ids    = [aws_security_group.ja3.id]
  key_name                  = aws_key_pair.ja3_ssh.key_name
  subnet_id                 = data.terraform_remote_state.vpc.outputs.engineering_subnet_id
  iam_instance_profile      = aws_iam_instance_profile.ja3.name
  user_data                 = <<-EOF
                              #!/bin/bash
                              sudo apt-get update && 
                              sudo apt install python3

                              EOF

  tags = {
      Name = "JA3"
  }

  lifecycle {
      ignore_changes = [
          "ami"
      ]
  }
}


resource "aws_security_group" "ja3" {
  name          = "JA3"
  description   = "Security Group for JA3"
  vpc_id        = data.terraform_remote_state.vpc.outputs.vpc_id

  tags = {
    Name = "JA3"
  }
}

resource "aws_security_group_rule" "ja3_allow_ssh" {
  type              = "ingress"
  from_port         = 22 
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [
    for name, cidr in data.terraform_remote_state.vpc.outputs.transit_gateway_routes:
    cidr
    if name != "it-protected-subnet"
  ]
  security_group_id = aws_security_group.ja3.id
}


resource "aws_security_group_rule" "ja3_allow_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [
    for name, cidr in data.terraform_remote_state.vpc.outputs.transit_gateway_routes:
    cidr
    if name != "it-protected-subnet"
  ]
  security_group_id = aws_security_group.ja3.id
}

resource "aws_security_group_rule" "ja3_allow_all_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.ja3.id
}


resource "aws_route53_record" "ja3" {
  zone_id = data.terraform_remote_state.vpc.outputs.route53_zone_id
  name    = format("ja3.%s", data.terraform_remote_state.vpc.outputs.domain_name)
  type    = "A"
  ttl     = 30

  records = [aws_instance.ja3.private_ip]
}

data "aws_iam_policy_document" "ja3_assume" {
    statement {
        effect = "Allow"
        principals { 
          type = "Service"
          identifiers = ["ec2.amazonaws.com"]
        }
        actions = ["sts:AssumeRole"]
    }
}

# https://www.terraform.io/docs/providers/aws/r/iam_role.html
resource "aws_iam_role" "ja3" {
  name                = "ja3-role"
  assume_role_policy  = data.aws_iam_policy_document.ja3_assume.json
}

# https://www.terraform.io/docs/providers/aws/r/s3_bucket.html
data "aws_iam_policy_document" "ja3_policy_document" {
    statement {
        sid = "globalRoute53"
        actions = [
          "route53:ListHostedZones",
          "route53:GetChange"
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "specificRoute53"
        actions = [
          "route53:ChangeResourceRecordSets"
        ]
        resources = [
          # Hardcoded because the public zone (that we need access to)
          # is made automatically by route53
          "arn:aws:route53:::hostedzone/Z37BBG38HWJEU8"
        ]
    }

    statement {
        sid = "dynamoEC2"
        actions = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        resources = [
          "arn:aws:dynamodb:us-east-1:624427452316:table/JA3Fingerprints"
        ]
    }
}

# https://www.terraform.io/docs/providers/aws/r/iam_policy.html
resource "aws_iam_policy" "ja3" {
  name        = "ja3-policy"
  path        = "/"
  description = "Policy for ja3"
  policy      = data.aws_iam_policy_document.ja3_policy_document.json
}

# https://www.terraform.io/docs/providers/aws/r/iam_role_policy_attachment.html
resource "aws_iam_role_policy_attachment" "ja3" {
  role        = aws_iam_role.ja3.name
  policy_arn  = aws_iam_policy.ja3.arn
}

# https://www.terraform.io/docs/providers/aws/r/iam_instance_profile.html
resource "aws_iam_instance_profile" "ja3" {
  name = "ja3"
  role = aws_iam_role.ja3.name

}
