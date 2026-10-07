variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "permitted_ip_range" {
  type    = string
  default = "31.0.0.0/8"
}

variable "container_port" {
  type    = number
  default = 7860
}