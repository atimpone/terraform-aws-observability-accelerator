output "vpc_private_subnet_cidr" {
  description = "VPC private subnet CIDR"
  value       = module.vpc.private_subnets_cidr_blocks
}

output "vpc_public_subnet_cidr" {
  description = "VPC public subnet CIDR"
  value       = module.vpc.public_subnets_cidr_blocks
}

output "vpc_cidr" {
  description = "VPC CIDR"
  value       = module.vpc.vpc_cidr_block
}

output "ec2_instance_id" {
  description = "EC2 Instance ID"
  value       = aws_instance.ADOTEC2TerraformInstance.id
}

output "ec2_instance_arn" {
  description = "EC2 arn"
  value       = aws_instance.ADOTEC2TerraformInstance.arn
}
