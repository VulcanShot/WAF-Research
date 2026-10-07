output "alb_dns_name" {
  value       = module.lab.alb_dns_name
  description = "Public ALB hostname to send test payloads to."
}

output "web_acl_arn" {
  value       = module.lab.web_acl_arn
  description = "ARN of the Web ACL fronting the ALB."
}

output "image_uri" {
  value       = module.lab.image_uri
  description = "ECR image URI (content-hash tagged) that the task runs."
}
