variable "name" {
  type        = string
  description = "Lab identifier; names every resource and the ECR repository. Keep <= 28 chars so derived ALB and target-group names stay within the 32-char AWS limit."
}

variable "aws_region" {
  type = string
}

variable "container_port" {
  type        = number
  description = "Port the container listens on and that the ALB forwards to."
}

variable "health_check_path" {
  type    = string
  default = "/"
}

variable "build_context" {
  type        = string
  description = "Docker build context directory, relative to the tf/ root module."
}

variable "dockerfile" {
  type        = string
  default     = null
  description = "Dockerfile path relative to the tf/ root module. Defaults to <build_context>/Dockerfile."
}

variable "waf_rule_file" {
  type        = string
  description = "Raw AWS WAFv2 rule JSON file (a single Rule object), relative to the tf/ root module."
}

variable "permitted_ip_range" {
  type    = string
  default = "31.0.0.0/8"
}

variable "host_placeholder" {
  type        = string
  default     = "DEFAULT_HOST_GUARD"
  description = "Token inside waf_rule_file substituted with the live ALB DNS name before the rule is applied."
}
