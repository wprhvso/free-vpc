resource "cloudflare_worker_script" "dashboard" {
  account_id         = var.cloudflare_account_id
  name               = "free-vpc-dashboard"
  content            = file("${path.module}/../../free-vpc-dashboard/worker-serve.js")
  module             = true
  compatibility_date = "2024-09-01"
}

resource "cloudflare_workers_domain" "dash_domain" {
  account_id = var.cloudflare_account_id
  zone_id    = "8fdf0e75be2ee4a86d28f9662b258e1b"
  hostname   = "dash.unsafie.com"
  service    = cloudflare_worker_script.dashboard.name
}

resource "cloudflare_zero_trust_access_application" "dash_app" {
  zone_id                   = "8fdf0e75be2ee4a86d28f9662b258e1b"
  name                      = "Free VPC Dashboard UI"
  type                      = "self_hosted"
  domain                    = "dash.unsafie.com"
  session_duration          = "24h"
  auto_redirect_to_identity = false

  policies = [
    cloudflare_zero_trust_access_policy.admin_ui.id
  ]
}
