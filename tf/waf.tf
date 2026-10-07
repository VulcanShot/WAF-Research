resource "aws_wafv2_web_acl" "main" {
  name        = "react2shell-protection-acl"
  description = "WAF rules targeting CVE-2025-55182 payload strings"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "React2ShellWAF"
    sampled_requests_enabled   = true
  }

  lifecycle {
    ignore_changes = [rule]
  }
}

resource "aws_wafv2_web_acl_association" "alb_assoc" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

resource "aws_wafv2_web_acl_rule" "main" {
  name        = "Block-React2Shell-Constructor"
  priority    = 1
  web_acl_arn = aws_wafv2_web_acl.main.arn

  action {
    block {}
  }

  statement {
    byte_match_statement {
      search_string         = "#constructor"
      positional_constraint = "CONTAINS"

      field_to_match {
        body {
          oversize_handling = "CONTINUE"
        }
      }

      text_transformation {
        priority = 0
        type     = "NONE"
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "BlockReact2ShellConstructor"
    sampled_requests_enabled   = true
  }
}
