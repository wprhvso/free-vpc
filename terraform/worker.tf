resource "cloudflare_worker_script" "orchestrator" {
  account_id         = var.cloudflare_account_id
  name               = "free-vpc-orchestrator"
  content            = file("${path.module}/../worker/index.js")
  module             = true
  compatibility_date = "2024-09-01"

  plain_text_binding {
    name = "REPO"
    text = var.github_repository
  }

  plain_text_binding {
    name = "TARGET_NODES"
    text = "20"
  }

  plain_text_binding {
    name = "BRANCH"
    text = "init-free-vpc"
  }

  secret_text_binding {
    name = "GITHUB_TOKEN"
    text = var.github_token
  }
}

resource "cloudflare_worker_cron_trigger" "orchestrator_cron" {
  account_id  = var.cloudflare_account_id
  script_name = cloudflare_worker_script.orchestrator.name
  schedules   = ["*/15 * * * *"]
}
