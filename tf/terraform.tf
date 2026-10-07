terraform {
  required_version = ">=1.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.58"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  # assume_role {
  #   role_arn     = ""
  #   session_name = ""
  # }
}