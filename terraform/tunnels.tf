resource "random_id" "tunnel_secret" {
  count       = 3
  byte_length = 32
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "mesh_tunnel" {
  count      = 3
  account_id = var.cloudflare_account_id
  name       = "ygg-mesh-${count.index + 1}"
  secret     = random_id.tunnel_secret[count.index].b64_std
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "mesh_config" {
  count      = 3
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.mesh_tunnel[count.index].id

  config {
    ingress_rule {
      hostname = "mesh${count.index + 1}.${var.cluster_domain}"
      service  = "http://127.0.0.1:9001"
    }
    ingress_rule {
      hostname = "gitops.${var.cluster_domain}"
      service  = "http://127.0.0.1:80"
    }
    ingress_rule {
      hostname = "headlamp.${var.cluster_domain}"
      service  = "http://127.0.0.1:80"
    }
    ingress_rule {
      hostname = "ui.${var.cluster_domain}"
      service  = "http://127.0.0.1:80"
    }
    ingress_rule {
      hostname = "*.${var.cluster_domain}"
      service  = "http://127.0.0.1:80"
    }
    ingress_rule {
      service = "http_status:404"
    }
  }
}

resource "cloudflare_record" "mesh_record" {
  count   = 3
  zone_id = var.cloudflare_zone_id
  name    = "mesh${count.index + 1}"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.mesh_tunnel[count.index].id}.cfargotunnel.com"
  proxied = true
}

resource "cloudflare_record" "ui_records" {
  for_each = toset(["gitops", "headlamp", "ui"])
  zone_id  = var.cloudflare_zone_id
  name     = each.key
  type     = "CNAME"
  content  = "${cloudflare_zero_trust_tunnel_cloudflared.mesh_tunnel[0].id}.cfargotunnel.com"
  proxied  = true
}

resource "cloudflare_record" "wildcard_record" {
  zone_id = var.cloudflare_zone_id
  name    = "*"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.mesh_tunnel[0].id}.cfargotunnel.com"
  proxied = true
}

resource "random_password" "ygg_password" {
  length  = 32
  special = false
}

resource "random_password" "k3s_token" {
  length  = 48
  special = false
}

resource "random_password" "rclone_crypt_password" {
  length  = 32
  special = false
}

resource "random_password" "s3_secret_key" {
  length  = 32
  special = false
}
