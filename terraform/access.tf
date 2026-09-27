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
  account_id       = var.cloudflare_account_id
  name             = "Warp Login App"
  type             = "warp"
  domain           = "${var.team_name}.cloudflareaccess.com/warp"
  session_duration = "24h"
  policies         = [cloudflare_zero_trust_access_policy.device_enrollment.id]
}

resource "cloudflare_split_tunnel" "default_exclude" {
  account_id = var.cloudflare_account_id
  mode       = "exclude"

  tunnels {
    address = "10.0.0.0/8"
  }
  tunnels {
    address = "169.254.0.0/16"
  }
  tunnels {
    address = "172.16.0.0/12"
  }
  tunnels {
    address = "192.0.0.0/24"
  }
  tunnels {
    address = "192.168.0.0/16"
  }
  tunnels {
    address = "224.0.0.0/24"
  }
  tunnels {
    address = "240.0.0.0/4"
  }
  tunnels {
    address = "255.255.255.255/32"
  }
  tunnels {
    address = "fd00::/8"
  }
  tunnels {
    address = "fe80::/10"
  }
  tunnels {
    address = "ff01::/16"
  }
  tunnels {
    address = "ff02::/16"
  }
  tunnels {
    address = "ff03::/16"
  }
  tunnels {
    address = "ff04::/16"
  }
  tunnels {
    address = "ff05::/16"
  }
}
