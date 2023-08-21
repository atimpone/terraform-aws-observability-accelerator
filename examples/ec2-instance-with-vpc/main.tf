# Inputs
# - variable for AMP id
#
# Steps
# 1. Create or identify AWSDistroOpenTelemetryPolicy policy
# 2. Create or identify AWSDistroOpenTelemetryRole role
#    https://registry.terraform.io/modules/terraform-aws-modules/iam/aws/latest
# 3. Create or identify Key Pair
# 4. Create or identify VPC, Subnets
#    https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest
# 5. Create or identify Security Groups
# 6. Create or identify EC2 IAM Instance Profile
# 7. Create or identify EC2 instance(s)
#    https://registry.terraform.io/modules/terraform-aws-modules/ec2-instance/aws/latest
#    a. SSH to instance and setup Node Exporter
#    b. SSH to instance and setup ADOT

provider "aws" {
  region = local.region
}

data "aws_availability_zones" "available" {}

locals {
  name         = basename(path.cwd)
  region       = var.aws_region

  vpc_cidr     = "10.0.0.0/16"
  azs          = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-observability/terraform-aws-observability-accelerator"
  }
}

#---------------------------------------------------------------
# Supporting Resources
#---------------------------------------------------------------


#---------------------------------------------------------------
# Create S3 bucket for upload of ADOT configuration scripts
#---------------------------------------------------------------
resource "random_id" "example" {
  byte_length = 8
}
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "adot-scripts-${random_id.example.hex}"
}

resource "aws_s3_object" "configure_adot" {
  bucket = module.s3_bucket.s3_bucket_id
  key    = "configure_adot.sh"
  source = "configure_adot.sh"
}

resource "aws_s3_object" "node_exporter_setup" {
  bucket = module.s3_bucket.s3_bucket_id
  key    = "node_exporter_setup.sh"
  source = "node_exporter_setup.sh"
}

#---------------------------------------------------------------
# IAM
# 1. Create or identify AWSDistroOpenTelemetryPolicy policy
# 2. Create or identify AWSDistroOpenTelemetryRole role
#  https://registry.terraform.io/modules/terraform-aws-modules/iam/aws/latest
#---------------------------------------------------------------
module "iam_policy" {
    source  = "terraform-aws-modules/iam/aws//modules/iam-policy"

    name        = "AWSDistroOpenTelemetryPolicy"
    path        = "/"
    description = "Policy used for EC2 instances that use ADOT"

    # Terraform's "jsonencode" function converts a
    # Terraform expression result to valid JSON syntax.
    policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "aps:ListWorkspaces",
                    "aps:DescribeWorkspace",
                    "iam:ListInstanceProfiles",
                    "logs:CreateLogStream",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents",
                    "ec2:Describe*",
                    "ec2:Search*",
                    "ec2:Get*",
                    "ssm:GetParameters",
                    "xray:GetSamplingTargets",
                    "xray:GetSamplingRules",
                    "xray:GetSamplingStatisticSummaries",
                    "xray:PutTelemetryRecords",
                    "xray:PutTraceSegments"
                ],
                "Resource": "*"
            },
            {
              "Effect": "Allow",
              "Action": "s3:GetObject",
              "Resource": "${module.s3_bucket.s3_bucket_arn}/*"
            }
        ]
    })
}

resource "aws_iam_role" "AWSDistroOpenTelemetryRole" {
  name = "AWSDistroOpenTelemetryRole"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Principal": {
            "Service": "ec2.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "AWSDistroOpenTelemetryRolePolicy-attach" {
  role       = aws_iam_role.AWSDistroOpenTelemetryRole.name
  policy_arn = module.iam_policy.arn
}

resource "aws_iam_role_policy_attachment" "AWSDistroOpenTelemetryRole-PrometheusPolicy-attach" {
  role       = aws_iam_role.AWSDistroOpenTelemetryRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonPrometheusRemoteWriteAccess"
}



#---------------------------------------------------------------
# 4. Create or identify VPC, Subnets
#---------------------------------------------------------------

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  # Manage so we can name
  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name}-default" }

  tags = local.tags
}

#---------------------------------------------------------------
# 5. Create or identify Security Groups
# 6. Create or identify EC2 IAM Instance Profile
#---------------------------------------------------------------
resource "aws_security_group" "ADOTEC2SecurityGroup" {
  name        = "ADOTEC2SecurityGroup"
  description = "ADOT EC2 Security Group (Allow SSH inbound traffic)"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description      = "SSH from VPC"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = [var.your_ip]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "DefaultSG"
  }
}

resource "aws_iam_instance_profile" "ADOTEC2InstanceProfile" {
  name = "ADOTEC2InstanceProfile"
  role = aws_iam_role.AWSDistroOpenTelemetryRole.name
}

#---------------------------------------------------------------
# Create EC2 instance(s)
#    https://registry.terraform.io/modules/terraform-aws-modules/ec2-instance/aws/latest
#---------------------------------------------------------------
data "aws_ami" "amazon-linux-2" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*"]
  }
}

resource "aws_instance" "ADOTEC2TerraformInstance" {

  ami                    = "${data.aws_ami.amazon-linux-2.id}"
  instance_type          = var.ec2_instance_type
  vpc_security_group_ids = [aws_security_group.ADOTEC2SecurityGroup.id]
  subnet_id              = element(module.vpc.public_subnets, 0)
  #key_name               = "${module.key_pair.key_pair_name}"

  iam_instance_profile = aws_iam_instance_profile.ADOTEC2InstanceProfile.name

  tags = {
    Name = "ADOTEC2TerraformInstance"
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"
    http_put_response_hop_limit = "3"
  }

  user_data = <<EOF
#!/bin/bash
echo "Updating instance"
sudo yum -y update

sudo yum -y install jq

# Update to AWS ClI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

echo "Copying scripts from S3 bucket"
if [ ! -f "/tmp/node_exporter_setup.sh" ]; then
  aws s3 cp s3://${module.s3_bucket.s3_bucket_id}/node_exporter_setup.sh /tmp/node_exporter_setup.sh
  chmod +x /tmp/node_exporter_setup.sh
  /tmp/node_exporter_setup.sh
fi

if [ ! -f "/tmp/configure_adot.sh" ]; then
  aws s3 cp s3://${module.s3_bucket.s3_bucket_id}/configure_adot.sh /tmp/configure_adot.sh
  chmod +x /tmp/configure_adot.sh
  /tmp/configure_adot.sh
fi

 EOF 
}