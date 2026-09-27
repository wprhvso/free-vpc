resource "cloudflare_zero_trust_access_policy" "device_enrollment" {
  account_id = var.cloudflare_account_id
  name       = "Allow Device Enrollment"
  decision   = "allow"

  include {
    email        = ["wprhvso@gmail.com"]
    email_domain = ["gmail.com"]
  }
}

resource "cloudflare_zero_trust_access_application" "warp_enrollment" {
  account_id           = var.cloudflare_account_id
  name                 = "Warp Login App"
  type                 = "warp"
  domain               = "${var.team_name}.cloudflareaccess.com/warp"
  app_launcher_visible = false
  allowed_idps         = ["636485b2-2a70-40e8-8e3e-758b36fe104b"]

  policies = [
    cloudflare_zero_trust_access_policy.device_enrollment.id
  ]
}
