# WAF lab TF harness

Serves a vulnerable app (any local Dockerfile, or any prebuilt image pullable
from a registry) on ECS Fargate behind an ALB, with an AWS WAFv2 Web ACL
attached to the ALB.

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

1. Drop the vuln's Dockerfile (and build context), or pick a prebuilt image to
   pull.
2. Drop its WAFv2 rule JSON (a single Rule object).
3. Add `labs/<vuln>.tfvars` with exactly one image source.

   Built here, pushed to a lab-owned ECR repository:

   ```hcl
   lab = {
     name              = "<vuln-id>"        # <= 28 chars (ALB/TG name limit)
     container_port    = <port>
     health_check_path = "/health"
     build_context     = "../<path>/to/dockerfile-dir"
     waf_rule_file     = "../<path>/rule.json"
   }
   ```

   Pulled from a registry, no local Docker needed:

   ```hcl
   lab = {
     name              = "<vuln-id>"
     container_port    = <port>
     health_check_path = "/health"
     image_url         = "ghcr.io/<owner>/<app>:<tag>"
     waf_rule_file     = "../<path>/rule.json"

     environment_variables = {
       UNSAFE_MODE = "1"
     }
   }
   ```

   `environment_variables` is optional on either shape, and is how you switch on
   whatever configuration the vulnerable app needs to be reachable.

4. `terraform apply -var-file=labs/<vuln>.tfvars`.

Switching labs in the same state recreates the stack for the new lab. To run two
at once, use separate Terraform workspaces (`terraform workspace new <lab>`).

## Notes

- Set `permitted_ip_range` in the lab object to your public IP; the ALB security
  group only admits that range on port 80.
- `build_context` and `image_url` are mutually exclusive; the apply fails if
  neither or both are set. ECR, the image build and the push only exist for a
  `build_context` lab.
- `image_url` is pulled by the Fargate task, so the registry has to allow
  anonymous pulls. Images on Docker Hub, GHCR and Quay qualify; a private
  registry needs credentials the task definition does not carry.
- `environment_variables` reaches the running container only; it is not passed
  to `docker build`. Values sit in plaintext in the task definition, the plan
  output and the state file, so put only throwaway lab credentials there.
- Changing `environment_variables` registers a new task definition revision and
  redeploys the service. `apply` returns before the new task passes health
  checks, so give it a minute or two.
