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
}
