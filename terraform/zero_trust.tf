resource "cloudflare_device_settings_policy" "free_vpc_mesh" {
  account_id           = var.cloudflare_account_id
  name                 = "Free VPC Mesh Nodes"
  description          = "Mesh routing policy with MASQUE"
  precedence           = 100
  match                = "identity.email == \"warp_connector@${var.team_name}.cloudflareaccess.com\""
  service_mode_v2_mode = "warp"
  tunnel_protocol      = "masque"
  allowed_to_leave     = true
}

resource "cloudflare_split_tunnel" "mesh_include" {
  account_id = var.cloudflare_account_id
  policy_id  = cloudflare_device_settings_policy.free_vpc_mesh.id
  mode       = "include"
  tunnels {
    address     = "100.96.0.0/12"
    description = "Mesh IP Range"
  }
  tunnels {
    address     = "10.0.1.0/24"
    description = "Free VPC Private CIDR"
  }
}

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

resource "cloudflare_split_tunnel" "default_include" {
  account_id = var.cloudflare_account_id
  mode       = "include"

  tunnels {
    address     = "100.96.0.0/12"
    description = "Mesh IPs"
  }
  tunnels {
    address     = "10.0.1.0/24"
    description = "Free VPC Private CIDR"
  }
}

resource "cloudflare_teams_rule" "allow_mesh_traffic" {
  account_id  = var.cloudflare_account_id
  name        = "Allow Free VPC Private Traffic"
  description = "Allow all L4 traffic to Mesh IPs and Private CIDR"
  action      = "allow"
  enabled     = true
  precedence  = 100
  filters     = ["l4"]
  traffic     = "net.dst.ip in {100.96.0.0/12 10.0.1.0/24}"
}
