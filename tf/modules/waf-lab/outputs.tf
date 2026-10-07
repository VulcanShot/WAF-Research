output "alb_dns_name" {
  value = aws_lb.alb.dns_name
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.main.arn
}

output "image_uri" {
  value = local.image_uri
}
