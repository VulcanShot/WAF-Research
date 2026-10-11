# WAF Research

Research into known CVEs to generate AWS WAFv2 rules.

## Vulnerabilities

CVE | Vulnerability | WCU |
--- | --- | --- |
CVE-2025-3248 | Unauthenticated RCE in Langflow `POST /api/v1/validate/code` | 40 |
CVE-2026-41242 | Code injection through a protobuf.js JSON-descriptor type name | 68 |

## Lab harness — `tf/`

Terraform that stands up one vulnerable app on ECS Fargate behind an ALB, with
the vuln's WAFv2 rule attached to the ALB's Web ACL and managed rules off. The
app comes either from a local Dockerfile or from a prebuilt public image.

```bash
terraform apply -var-file=labs/<lab>.tfvars
terraform output -raw alb_dns_name
terraform destroy -var-file=labs/<lab>.tfvars
```

## Traffic runner — `traffic-runner/`

Replays a `traffic.yaml` corpus against a target and reports whether the WAF
behaved: exploits blocked, benign traffic allowed. Exploit success is confirmed
by the lab app raising `SINK_REACHED`.

```bash
python runner.py ../<vuln>/traffic.yaml --target http://<alb-dns> \
                 --resolver resolvers/<cve>.py --format markdown
```