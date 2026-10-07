module "lab" {
  source = "./modules/waf-lab"

  name               = var.lab.name
  aws_region         = var.aws_region
  container_port     = var.lab.container_port
  health_check_path  = var.lab.health_check_path
  build_context      = var.lab.build_context
  dockerfile         = var.lab.dockerfile
  waf_rule_file      = var.lab.waf_rule_file
  permitted_ip_range = var.lab.permitted_ip_range
}
