locals {
  rule_file = abspath("${path.root}/${var.waf_rule_file}")
}

resource "aws_wafv2_web_acl" "main" {
  name        = "${var.name}-acl"
  description = "WAF protecting the ${var.name} lab."
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule_json = jsonencode([
    jsondecode(replace(file(local.rule_file), var.host_placeholder, aws_lb.alb.dns_name))
  ])

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${replace(var.name, "-", "")}WebAcl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
