module "lab" {
  source = "./modules/waf-lab"

  name                              = var.lab.name
  aws_region                        = var.aws_region
  container_port                    = var.lab.container_port
  health_check_path                 = var.lab.health_check_path
  health_check_grace_period_seconds = var.lab.health_check_grace_period_seconds
  build_context                     = var.lab.build_context
  dockerfile                        = var.lab.dockerfile
  image_url                         = var.lab.image_url
  environment_variables             = var.lab.environment_variables
  cpu_units                         = var.lab.cpu_units
  memory_mib                        = var.lab.memory_mib
  waf_rule_file                     = var.lab.waf_rule_file
  permitted_ip_range                = var.lab.permitted_ip_range
}
