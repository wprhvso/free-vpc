resource "cloudflare_workers_domain" "vm_domain" {
  account_id = var.cloudflare_account_id
  zone_id    = var.cloudflare_zone_id
  hostname   = "vm.${var.cluster_domain}"
  service    = cloudflare_worker_script.orchestrator.name
}

resource "cloudflare_zero_trust_access_service_token" "orchestrator_token" {
  account_id = var.cloudflare_account_id
  name       = "Free VPC Automation Service Token"
  duration   = "8760h"
}

resource "cloudflare_zero_trust_access_policy" "service_auth" {
  account_id = var.cloudflare_account_id
  name       = "Allow Service Token Access"
  decision   = "non_identity"

  include {
    service_token = [cloudflare_zero_trust_access_service_token.orchestrator_token.id]
  }
}

resource "cloudflare_zero_trust_access_policy" "admin_ui" {
  account_id = var.cloudflare_account_id
  name       = "Allow Admin Browser Access"
  decision   = "allow"

  include {
    email = var.admin_email != "" ? [var.admin_email] : ["admin@${var.cluster_domain}"]
  }
}

resource "cloudflare_zero_trust_access_application" "vm_app" {
  account_id                = var.cloudflare_account_id
  name                      = "Free VPC Unified Portal"
  type                      = "self_hosted"
  domain                    = "vm.${var.cluster_domain}"
  session_duration          = "24h"
  auto_redirect_to_identity = false

  policies = [
    cloudflare_zero_trust_access_policy.admin_ui.id,
    cloudflare_zero_trust_access_policy.service_auth.id
  ]
}
