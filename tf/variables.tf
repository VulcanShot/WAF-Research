variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "lab" {
  type = object({
    name                  = string
    container_port        = number
    health_check_path     = optional(string, "/")
    build_context         = optional(string)
    dockerfile            = optional(string)
    image_url             = optional(string)
    environment_variables = optional(map(string), {})
    waf_rule_file         = string
    permitted_ip_range    = optional(string, "31.0.0.0/8")
  })
  description = "The vulnerability lab to stand up. Select one per apply with -var-file=labs/<lab>.tfvars."

  validation {
    condition     = (var.lab.build_context != null) != (var.lab.image_url != null)
    error_message = "Set exactly one image source on the lab: build_context to build locally, or image_url to pull a prebuilt image."
  }

  validation {
    condition     = var.lab.dockerfile == null || var.lab.build_context != null
    error_message = "dockerfile only applies to a locally built lab; it needs build_context."
  }
}
