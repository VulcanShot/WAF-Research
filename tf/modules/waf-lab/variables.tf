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

variable "health_check_grace_period_seconds" {
  type        = number
  default     = null
  description = "How long the service ignores load balancer health checks after a task starts. Covers a slow-booting app that would otherwise be cycled mid-startup."
}

variable "cpu_units" {
  type        = number
  default     = 256
  description = "Fargate CPU units for the task; 1024 units is one vCPU."
}

variable "memory_mib" {
  type        = number
  default     = 512
  description = "Fargate task memory in MiB. Which values are legal depends on cpu_units."
}

variable "build_context" {
  type        = string
  default     = null
  description = "Docker build context directory, relative to the tf/ root module. Set this to build and push the image to a lab-owned ECR repository; leave null to run image_url instead."
}

variable "dockerfile" {
  type        = string
  default     = null
  description = "Dockerfile path relative to the tf/ root module. Defaults to <build_context>/Dockerfile."
}

variable "image_url" {
  type        = string
  default     = null
  description = "Registry URL of a prebuilt image the task runs as-is, such as ghcr.io/owner/app:1.2.3. Set this instead of build_context; the registry must allow anonymous pulls."
}

variable "environment_variables" {
  type        = map(string)
  default     = {}
  description = "Environment variables set on the running container. Stored in plaintext on the task definition."
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
