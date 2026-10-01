output "mesh_tunnel_tokens" {
  value     = cloudflare_zero_trust_tunnel_cloudflared.mesh_tunnel[*].tunnel_token
  sensitive = true
}

output "cf_tunnel_token_1" {
  value     = cloudflare_zero_trust_tunnel_cloudflared.mesh_tunnel[0].tunnel_token
  sensitive = true
}

output "cf_tunnel_token_2" {
  value     = cloudflare_zero_trust_tunnel_cloudflared.mesh_tunnel[1].tunnel_token
  sensitive = true
}

output "cf_tunnel_token_3" {
  value     = cloudflare_zero_trust_tunnel_cloudflared.mesh_tunnel[2].tunnel_token
  sensitive = true
}

output "ygg_password" {
  value     = random_password.ygg_password.result
  sensitive = true
}

output "k3s_token" {
  value     = random_password.k3s_token.result
  sensitive = true
}

output "rclone_crypt_password" {
  value     = random_password.rclone_crypt_password.result
  sensitive = true
}

output "s3_secret_key" {
  value     = random_password.s3_secret_key.result
  sensitive = true
}

output "gitops_url" {
  value = "https://gitops.${var.cluster_domain}"
}

output "headlamp_url" {
  value = "https://headlamp.${var.cluster_domain}"
}

output "ui_url" {
  value = "https://ui.${var.cluster_domain}"
}
