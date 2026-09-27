output "device_policy_id" {
  value = cloudflare_device_settings_policy.free_vpc_mesh.id
}

output "split_tunnel_id" {
  value = cloudflare_split_tunnel.mesh_include.id
}

output "access_app_id" {
  value = cloudflare_zero_trust_access_application.warp_enrollment.id
}

output "access_policy_id" {
  value = cloudflare_zero_trust_access_policy.device_enrollment.id
}
