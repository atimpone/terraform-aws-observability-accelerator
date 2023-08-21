variable "aws_region" {
  description = "AWS Region"
  type        = string
}
variable "ec2_instance_type" {
  description = "Instance type for the EC2 instance"
  type        = string
  default     = "t2.micro"
}

variable "your_ip" {
  description = "Enter your public IP address (i.e. 104.230.22.104/32)"
  type        = string
  default = "104.230.22.104/32"
}
