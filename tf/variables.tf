variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "lab" {
  type = object({
    name               = string
    container_port     = number
    health_check_path  = optional(string, "/")
    build_context      = string
    dockerfile         = optional(string)
    waf_rule_file      = string
    permitted_ip_range = optional(string, "31.0.0.0/8")
  })
  description = "The vulnerability lab to stand up. Select one per apply with -var-file=labs/<lab>.tfvars."
}
