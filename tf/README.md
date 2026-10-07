# WAF lab TF harness

Serves a vulnerable app (any local Dockerfile) on ECS Fargate behind an ALB, with
an AWS WAFv2 Web ACL attached to the ALB. 

```bash
# Create
terraform apply -var-file <.tfvar>

# Get DNS name
terraform output -raw alb_dns_name

# Destroy
terraform destroy -var-file=labs/<lab>.tfvars
```

The WAF rule's host guard is pinned to this ALB automatically: the
`DEFAULT_HOST_GUARD` token in the rule JSON is substituted with
the live ALB DNS name at apply time.

## Add another vulnerability

No `.tf` edits needed:

1. Drop the vuln's Dockerfile (and build context)
2. Drop its WAFv2 rule JSON (a single Rule object).
3. Add `labs/<vuln>.tfvars`:

   ```hcl
   lab = {
     name              = "<vuln-id>"        # <= 28 chars (ALB/TG name limit)
     container_port    = <port>
     health_check_path = "/health"
     build_context     = "../<path>/to/dockerfile-dir"
     waf_rule_file     = "../<path>/rule.json"
   }
   ```

4. `terraform apply -var-file=labs/<vuln>.tfvars`.

Switching labs in the same state recreates the stack for the new lab. To run two
at once, use separate Terraform workspaces (`terraform workspace new <lab>`).

## Notes

- Set `permitted_ip_range` in the lab object to your public IP; the ALB security
  group only admits that range on port 80.
