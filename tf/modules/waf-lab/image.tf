locals {
  builds_image = var.build_context != null
}

resource "aws_ecr_repository" "lab" {
  count        = local.builds_image ? 1 : 0
  name         = var.name
  force_delete = true
}

locals {
  context_dir  = local.builds_image ? abspath("${path.root}/${var.build_context}") : ""
  dockerfile   = !local.builds_image ? "" : (var.dockerfile != null ? abspath("${path.root}/${var.dockerfile}") : "${local.context_dir}/Dockerfile")
  context_hash = local.builds_image ? substr(sha1(join("", [for f in fileset(local.context_dir, "**") : filesha256("${local.context_dir}/${f}")])), 0, 12) : ""
  registry     = local.builds_image ? split("/", aws_ecr_repository.lab[0].repository_url)[0] : ""
  image_uri    = local.builds_image ? "${aws_ecr_repository.lab[0].repository_url}:${local.context_hash}" : var.image_url
}

resource "terraform_data" "build_push" {
  count = local.builds_image ? 1 : 0

  triggers_replace = {
    image_uri = local.image_uri
  }

  provisioner "local-exec" {
    interpreter = ["pwsh", "-NoProfile", "-Command"]

    environment = {
      REGISTRY   = local.registry
      IMAGE_URI  = local.image_uri
      REGION     = var.aws_region
      CONTEXT    = local.context_dir
      DOCKERFILE = local.dockerfile
    }

    command = <<-EOT
      $ErrorActionPreference = 'Stop'
      aws ecr get-login-password --region $env:REGION | docker login --username AWS --password-stdin $env:REGISTRY
      if ($LASTEXITCODE -ne 0) { throw 'docker login failed' }
      docker build -f $env:DOCKERFILE -t $env:IMAGE_URI $env:CONTEXT
      if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }
      docker push $env:IMAGE_URI
      if ($LASTEXITCODE -ne 0) { throw 'docker push failed' }
    EOT
  }
}
