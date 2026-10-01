resource "cloudflare_zero_trust_access_policy" "device_enrollment" {
  account_id = var.cloudflare_account_id
  name       = "Allow Device Enrollment"
  decision   = "allow"

  include {
    email = var.admin_email != "" ? [var.admin_email] : ["admin@${var.cluster_domain}"]
  }
}

resource "cloudflare_zero_trust_access_application" "warp_enrollment" {
  account_id           = var.cloudflare_account_id
  name                 = "Warp Login App"
  type                 = "warp"
  domain               = "${var.team_name}.cloudflareaccess.com/warp"
  app_launcher_visible = false

  policies = [
    cloudflare_zero_trust_access_policy.device_enrollment.id
  ]
}
